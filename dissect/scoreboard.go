package dissect

import "github.com/rs/zerolog/log"

type Scoreboard struct {
	Players []ScoreboardPlayer
}

type ScoreboardPlayer struct {
	ID               []byte
	Score            uint32
	Assists          uint32
	AssistsFromRound uint32
}

// this function fixes kills that were previously recorded as elims
func readScoreboardKills(r *Reader) error {
	kills, err := r.Uint32()
	if err != nil {
		return err
	}
	if err := r.Skip(30); err != nil {
		return err
	}
	id, err := r.Bytes(4)
	if err != nil {
		return err
	}
	idx := r.PlayerIndexByID(id)
	if idx != -1 {
		username := r.Header.Players[idx].Username
		r.lastKillerFromScoreboard = username
		log.Warn().
			Str("username", username).
			Uint32("kills", kills).
			Msg("scoreboard_kill")
	}
	return nil
}

func readScoreboardAssists(r *Reader) error {
	assists, err := r.Uint32()
	if err != nil {
		return err
	}
	if assists == 0 {
		return nil
	}
	if err = r.Skip(30); err != nil {
		return err
	}
	id, err := r.Bytes(4)
	if err != nil {
		return err
	}
	idx := r.PlayerIndexByID(id)
	username := "N/A"
	if idx != -1 {
		username = r.Header.Players[idx].Username
		r.Scoreboard.Players[idx].Assists = assists
		r.Scoreboard.Players[idx].AssistsFromRound++
	}
	log.Debug().
		Uint32("assists", assists).
		Str("username", username).
		Msg("scoreboard_assists")
	return nil
}

func readScoreboardScore(r *Reader) error {
	// Score event binary layout: 23 [4B entity] 00000000 EC DA 4F 80 04 [4B score]
	// Pattern match ends at EC DA 4F 80, r.offset is just past the pattern.
	// Entity ID is at: pattern_start - 9 bytes (1B tag + 4B entity + 4B zeros)
	patternEnd := r.offset // just past the 4-byte pattern
	score, err := r.Uint32()
	if err != nil {
		return err
	}
	if score == 0 {
		return nil
	}

	// Identify player from the entity ID before the property hash.
	// Layout: 23 [4B entity] 00000000 EC DA 4F 80 04 [4B score]
	// The score entity ID = player's DissectID with byte[0] decremented by 4.
	username := "N/A"
	entityOffset := patternEnd - 12 // 4(pattern) + 4(zeros) + 4(entity) = 12 bytes back
	if entityOffset >= 0 && entityOffset+4 <= len(r.b) {
		scoreEid := r.b[entityOffset : entityOffset+4]
		// Convert score entity to DissectID by adding 4 to byte[0]
		dissectID := make([]byte, 4)
		copy(dissectID, scoreEid)
		dissectID[0] += 4
		idx := r.PlayerIndexByID(dissectID)
		if idx != -1 {
			username = r.Header.Players[idx].Username
			r.Scoreboard.Players[idx].Score = score
		}
	}

	// Track score-based activities for Y11S1+
	if r.Header.CodeVersion >= Y11S1 && username != "N/A" {
		r.trackScoreActivity(score, username)
	}
	log.Debug().
		Uint32("score", score).
		Str("username", username).
		Msg("scoreboard_score")
	return nil
}
