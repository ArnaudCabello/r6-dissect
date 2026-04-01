package dissect

import (
	"math"
	"sort"

	"github.com/rs/zerolog/log"
)

// Reinforcement represents a single reinforcement placement during the round.
type Reinforcement struct {
	Username      string  `json:"username"`      // player who placed it (from position gap detection)
	X             float32 `json:"x"`             // player position at placement time
	Y             float32 `json:"y"`
	Z             float32 `json:"z"`
	Time          string  `json:"time"`          // game clock formatted
	TimeInSeconds float64 `json:"timeInSeconds"` // game clock countdown value
	Remaining     int     `json:"remaining"`     // reinforcements remaining after this placement
}

// readReinforcementCounter is triggered by the property hash 67 DE 20 F8.
func readReinforcementCounter(r *Reader) error {
	remaining, err := r.Uint32()
	if err != nil {
		return err
	}

	prev := r.lastReinfCount
	if prev < 0 {
		r.lastReinfCount = int(remaining)
		log.Debug().Int("remaining", int(remaining)).Msg("reinforcement_counter_init")
		return nil
	}

	if int(remaining) < prev {
		r.pendingReinforcements = append(r.pendingReinforcements, Reinforcement{
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
			Remaining:     int(remaining),
		})
		log.Debug().
			Int("remaining", int(remaining)).
			Str("time", r.timeRaw).
			Msg("reinforcement_placed")
	}

	r.lastReinfCount = int(remaining)
	return nil
}

// posGap represents a gap in a player's position data stream.
type posGap struct {
	player      string
	startElapsed float64
	endElapsed   float64
	duration     float64
	x, y, z      float32
}

// resolveReinforcementPlayers assigns players to reinforcements by detecting
// gaps in position data. During the ~4-second reinforcement animation, the
// game stops sending position updates, creating a distinctive gap.
func (r *Reader) resolveReinforcementPlayers() {
	if len(r.pendingReinforcements) == 0 {
		return
	}

	var defenders []string
	for _, p := range r.Header.Players {
		team := r.Header.Teams[p.TeamIndex]
		if team.Role == Defense {
			defenders = append(defenders, p.Username)
		}
	}
	if len(defenders) == 0 {
		r.Reinforcements = r.pendingReinforcements
		return
	}

	// Build global gameClock -> elapsed mapping
	gcToElapsed := make(map[int][]float64)
	for _, positions := range r.PlayerPositions {
		for _, p := range positions {
			gc := int(p.GameClock)
			if gc >= 0 {
				gcToElapsed[gc] = append(gcToElapsed[gc], p.TimeInSeconds)
			}
		}
	}
	gcMedian := make(map[int]float64)
	for gc, vals := range gcToElapsed {
		sort.Float64s(vals)
		gcMedian[gc] = vals[len(vals)/2]
	}
	resolveGC := func(gc float64) float64 {
		igc := int(gc)
		if e, ok := gcMedian[igc]; ok {
			return e
		}
		lo, hi := -1, -1
		for g := range gcMedian {
			if g <= igc && (lo == -1 || g > lo) {
				lo = g
			}
			if g >= igc && (hi == -1 || g < hi) {
				hi = g
			}
		}
		if lo >= 0 && hi >= 0 && lo != hi {
			frac := float64(igc-lo) / float64(hi-lo)
			return gcMedian[lo] + frac*(gcMedian[hi]-gcMedian[lo])
		}
		if lo >= 0 {
			return gcMedian[lo]
		}
		if hi >= 0 {
			return gcMedian[hi]
		}
		return 0
	}

	// Find reinforcement-candidate gaps (3.0-5.5s) in each defender's position data.
	// During the reinforcement animation, the game stops sending position updates,
	// creating a distinctive gap.
	var allGaps []posGap
	for _, defender := range defenders {
		positions, ok := r.PlayerPositions[defender]
		if !ok || len(positions) < 10 {
			continue
		}
		sortedPos := make([]PlayerPosition, len(positions))
		copy(sortedPos, positions)
		sort.Slice(sortedPos, func(i, j int) bool {
			return sortedPos[i].TimeInSeconds < sortedPos[j].TimeInSeconds
		})

		for i := 1; i < len(sortedPos); i++ {
			dt := sortedPos[i].TimeInSeconds - sortedPos[i-1].TimeInSeconds
			if dt >= 3.0 && dt <= 5.5 {
				gcBefore := sortedPos[i-1].GameClock
				gcAfter := sortedPos[i].GameClock
				// Filter artifacts: skip gaps crossing phase boundaries
				if gcBefore == 0 && gcAfter > 30 {
					continue
				}
				if gcBefore < 5 && gcAfter > 100 {
					continue
				}

				allGaps = append(allGaps, posGap{
					player:       defender,
					startElapsed: sortedPos[i-1].TimeInSeconds,
					endElapsed:   sortedPos[i].TimeInSeconds,
					duration:     dt,
					x:            sortedPos[i-1].X,
					y:            sortedPos[i-1].Y,
					z:            sortedPos[i-1].Z,
				})
			}
		}
	}

	nReinf := len(r.pendingReinforcements)

	// Sort gaps by end time (chronological order of animation completion).
	// The reinforcement counter fires in the same chronological order,
	// so the Nth gap ending = the Nth reinforcement.
	sort.Slice(allGaps, func(i, j int) bool {
		return allGaps[i].endElapsed < allGaps[j].endElapsed
	})

	// We have more gaps than reinforcements (other animations also create gaps).
	// Use the reinforcement counter timing to select which gaps are reinforcements.
	// Strategy: match each reinforcement to the closest gap by elapsed time,
	// processing in chronological order.
	reinfElapsed := make([]float64, nReinf)
	for i, reinf := range r.pendingReinforcements {
		reinfElapsed[i] = resolveGC(reinf.TimeInSeconds)
	}

	// Process reinforcements in chronological order (earliest first)
	reinfOrder := make([]int, nReinf)
	for i := range reinfOrder {
		reinfOrder[i] = i
	}
	sort.Slice(reinfOrder, func(a, b int) bool {
		return reinfElapsed[reinfOrder[a]] < reinfElapsed[reinfOrder[b]]
	})

	// For each reinforcement, find the best unused gap.
	// Prefer gaps whose end time is close to the reinforcement elapsed time.
	usedGaps := make(map[int]bool)
	for _, ri := range reinfOrder {
		re := reinfElapsed[ri]

		bestIdx := -1
		bestCost := math.MaxFloat64

		for gi, gap := range allGaps {
			if usedGaps[gi] {
				continue
			}
			// Primary: distance between gap end and reinforcement elapsed time
			dist := math.Abs(gap.endElapsed - re)
			cost := dist

			if cost < bestCost {
				bestCost = cost
				bestIdx = gi
			}
		}

		if bestIdx >= 0 {
			usedGaps[bestIdx] = true
			gap := allGaps[bestIdx]
			r.pendingReinforcements[ri].Username = gap.player
			r.pendingReinforcements[ri].X = gap.x
			r.pendingReinforcements[ri].Y = gap.y
			r.pendingReinforcements[ri].Z = gap.z

			log.Debug().
				Str("username", gap.player).
				Str("time", r.pendingReinforcements[ri].Time).
				Float64("gap_start", gap.startElapsed).
				Float64("gap_end", gap.endElapsed).
				Float64("gap_duration", gap.duration).
				Int("remaining", r.pendingReinforcements[ri].Remaining).
				Msg("reinforcement_attributed")
		}
	}

	r.Reinforcements = r.pendingReinforcements
}
