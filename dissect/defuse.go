package dissect

import (
	"math"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

func readDefuserTimer(r *Reader) error {
	timer, err := r.String()
	if err != nil {
		return err
	}

	if r.Header.CodeVersion >= Y11S1 {
		return r.readDefuserTimerY11(timer)
	}

	if err = r.Skip(34); err != nil {
		return err
	}
	id, err := r.Bytes(4)
	if err != nil {
		return err
	}
	i := r.PlayerIndexByID(id)
	a := DefuserPlantStart
	if r.planted {
		a = DefuserDisableStart
	}
	if i > -1 {
		u := MatchUpdate{
			Type:          a,
			Username:      r.Header.Players[i].Username,
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
		}
		r.MatchFeedback = append(r.MatchFeedback, u)
		log.Debug().Interface("match_update", u).Send()
		r.lastDefuserPlayerIndex = i
	}
	// TODO: 0.00 can be present even if defuser was not disabled.
	if !strings.HasPrefix(timer, "0.00") {
		return nil
	}
	a = DefuserDisableComplete
	if !r.planted {
		a = DefuserPlantComplete
		r.planted = true
	}
	u := MatchUpdate{
		Type:          a,
		Username:      r.Header.Players[r.lastDefuserPlayerIndex].Username,
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
	}
	r.MatchFeedback = append(r.MatchFeedback, u)
	log.Debug().Interface("match_update", u).Send()
	return nil
}

// readDefuserTimerY11 handles the new defuser timer format in Y11S1+.
// The timer counts down from ~7.0 to 0.0 for both planting and defusing.
// The player ID is no longer directly embedded in the timer packet.
func (r *Reader) readDefuserTimerY11(timer string) error {
	if timer == "" {
		return nil
	}

	timerVal, err := strconv.ParseFloat(timer, 64)
	if err != nil {
		return nil
	}

	// Detect the start of a plant/defuse countdown (timer near 7.0).
	// Identify the interacting player from a nearby entity ID.
	if timerVal > 6.9 {
		if !r.defuserTimerSeen {
			// First countdown = plant
			r.defuserTimerSeen = true
			r.defuserPlantUsername = r.findDefuserPlayer()
		} else if r.planted && r.defuserDisableUsername == "" {
			// Subsequent countdown after plant = defuse attempt
			r.defuserDisableUsername = r.findDefuserPlayer()
		}
	}

	// Detect plant/defuse completion when timer reaches near 0.
	// The threshold varies by code version: older Y11S1 builds don't
	// count all the way to 0.
	threshold := 0.01
	if r.Header.CodeVersion < Y11S1Patch2 {
		threshold = 0.05
	}
	if timerVal >= threshold {
		return nil
	}

	if !r.planted {
		r.planted = true
		username := r.defuserPlantUsername
		if username == "" {
			username = r.findPlayerByRole(Attack)
		}
		u := MatchUpdate{
			Type:          DefuserPlantComplete,
			Username:      username,
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
		}
		r.MatchFeedback = append(r.MatchFeedback, u)
		log.Debug().Interface("match_update", u).Send()
	} else if !r.defuserDisabled {
		r.defuserDisabled = true
		username := r.defuserDisableUsername
		if username == "" {
			username = r.findPlayerByRole(Defense)
		}
		u := MatchUpdate{
			Type:          DefuserDisableComplete,
			Username:      username,
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
		}
		r.MatchFeedback = append(r.MatchFeedback, u)
		log.Debug().Interface("match_update", u).Send()
	}

	return nil
}

// findDefuserPlayer identifies the player interacting with the defuser
// by searching backwards from the current offset for an entity ID
// (pattern: 0x23 + 4-byte ID) whose last 3 bytes match the DissectID
// suffix shared by all players, then finding the player whose first
// DissectID byte is closest to the entity's first byte.
func (r *Reader) findDefuserPlayer() string {
	if len(r.Header.Players) == 0 {
		return ""
	}
	// Determine the common DissectID suffix (last 3 bytes)
	// Most players share the same suffix; find the most common one
	suffixCount := make(map[[3]byte]int)
	for _, p := range r.Header.Players {
		if len(p.DissectID) == 4 {
			var key [3]byte
			copy(key[:], p.DissectID[1:4])
			suffixCount[key]++
		}
	}
	var suffix [3]byte
	bestCount := 0
	for s, c := range suffixCount {
		if c > bestCount {
			suffix = s
			bestCount = c
		}
	}
	if bestCount == 0 {
		return ""
	}

	searchStart := r.offset - 200
	if searchStart < 0 {
		searchStart = 0
	}

	// Search backwards from current offset for 0x23 + XX + suffix
	entityByte := -1
	for i := r.offset - 1; i >= searchStart; i-- {
		if i+4 < len(r.b) && r.b[i] == 0x23 &&
			r.b[i+2] == suffix[0] && r.b[i+3] == suffix[1] && r.b[i+4] == suffix[2] {
			entityByte = int(r.b[i+1])
			break
		}
	}
	if entityByte >= 0 {
		// Find the player whose DissectID first byte is closest
		closestDist := math.MaxInt
		closestPlayer := ""
		for _, p := range r.Header.Players {
			if len(p.DissectID) == 4 && p.DissectID[1] == suffix[0] &&
				p.DissectID[2] == suffix[1] && p.DissectID[3] == suffix[2] {
				dist := int(math.Abs(float64(int(p.DissectID[0]) - entityByte)))
				if dist < closestDist {
					closestDist = dist
					closestPlayer = p.Username
				}
			}
		}
		if closestPlayer != "" {
			return closestPlayer
		}
	}

	return ""
}

// findPlayerByRole returns the username of a player on the team with the given role.
func (r *Reader) findPlayerByRole(role TeamRole) string {
	for _, p := range r.Header.Players {
		if r.Header.Teams[p.TeamIndex].Role == role {
			return p.Username
		}
	}
	return ""
}
