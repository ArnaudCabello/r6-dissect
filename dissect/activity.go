package dissect

import (
	"github.com/rs/zerolog/log"
)

// ActivityType represents a player action on the map.
type ActivityType string

const (
	ActivityReinforce ActivityType = "reinforce"
	ActivityGadget    ActivityType = "gadget"
	ActivityKill      ActivityType = "kill"
	ActivityUnknown   ActivityType = "unknown"
)

// Activity represents a located player action during the round.
type Activity struct {
	Type          ActivityType `json:"type"`
	Username      string       `json:"username"`
	X             float32      `json:"x"`
	Y             float32      `json:"y"`
	Z             float32      `json:"z"`
	ScoreDelta    int          `json:"scoreDelta"`
	TotalScore    int          `json:"totalScore"`
	Time          string       `json:"time"`
	TimeInSeconds float64      `json:"timeInSeconds"`
}

// scoreToActivity maps a score delta to an activity type.
func scoreToActivity(delta int) ActivityType {
	switch {
	case delta == 10:
		return ActivityReinforce
	case delta == 20:
		return ActivityGadget
	case delta >= 50 && delta <= 100:
		return ActivityKill
	default:
		return ActivityUnknown
	}
}

// trackScoreActivity is called from readScoreboardScore for Y11S1+.
func (r *Reader) trackScoreActivity(score uint32) {
	// Find the recording player
	playerIdx := -1
	for i, p := range r.Header.Players {
		if p.ProfileID == r.Header.RecordingProfileID {
			playerIdx = i
			break
		}
	}
	if playerIdx < 0 && len(r.Header.Players) == 1 {
		playerIdx = 0
	}
	if playerIdx < 0 {
		return
	}

	username := r.Header.Players[playerIdx].Username
	lastScore := r.lastScores[username]
	delta := int(score) - lastScore
	r.lastScores[username] = int(score)

	if delta <= 0 {
		return
	}

	actType := scoreToActivity(delta)

	// Find the player's position at this activity's time.
	// Position data and time/score events are in separate byte regions,
	// so we estimate the position index from elapsed time proportion.
	x, y, z := r.positionAtTime(username, r.time)

	act := Activity{
		Type:          actType,
		Username:      username,
		X:             x,
		Y:             y,
		Z:             z,
		ScoreDelta:    delta,
		TotalScore:    int(score),
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
	}

	r.Activities = append(r.Activities, act)
	log.Debug().
		Str("type", string(actType)).
		Str("username", username).
		Int("delta", delta).
		Int("total", int(score)).
		Float32("x", x).Float32("y", y).Float32("z", z).
		Msg("activity")
}

// positionAtTime estimates the player's position at a given countdown time.
// Positions are stored in chronological order (first = round start, last = round end).
// Time counts down (e.g., 44 = round start, 0 = round end).
func (r *Reader) positionAtTime(username string, countdownTime float64) (float32, float32, float32) {
	allPositions, ok := r.PlayerPositions[username]
	if !ok || len(allPositions) < 2 {
		return 0, 0, 0
	}

	// Filter to valid positions (skip near-zero noise and dead positions)
	positions := make([]PlayerPosition, 0, len(allPositions))
	for _, p := range allPositions {
		absX := p.X; if absX < 0 { absX = -absX }
		absY := p.Y; if absY < 0 { absY = -absY }
		if (absX > 1 || absY > 1) && p.Z > -50 {
			positions = append(positions, p)
		}
	}
	if len(positions) < 2 {
		return 0, 0, 0
	}

	// maxTimeValue is the highest countdown timer seen (e.g., 44 for prep phase)
	maxTime := r.maxTimeValue
	if maxTime <= 0 {
		maxTime = 45 // default
	}

	// Elapsed fraction: 0 = round start (maxTime remaining), 1 = round end (0 remaining)
	elapsed := 1.0 - (countdownTime / maxTime)
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed > 1 {
		elapsed = 1
	}

	idx := int(elapsed * float64(len(positions)-1))
	if idx >= len(positions) {
		idx = len(positions) - 1
	}

	return positions[idx].X, positions[idx].Y, positions[idx].Z
}
