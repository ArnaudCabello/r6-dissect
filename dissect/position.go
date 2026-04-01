package dissect

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
)

// PlayerPosition represents a player's position at a point in time.
type PlayerPosition struct {
	X             float32 `json:"x"`
	Y             float32 `json:"y"`
	Z             float32 `json:"z"`
	Time          string  `json:"time"`
	TimeInSeconds float64 `json:"timeInSeconds"`
	offset        int     // byte offset in data stream, used for ordering
}

var positionMarker = []byte{0x60, 0x73, 0x85, 0xFE}

type entityInfo struct {
	key        entityKey
	positions  []PlayerPosition
	movement   float64
	lastOffset int
}

func firstOffset(positions []PlayerPosition) int {
	if len(positions) == 0 {
		return 0
	}
	return positions[0].offset
}

// entityPositions accumulates positions by full 4-byte entity ID during parsing.
// Resolved to player names in resolvePositionEntities().
type entityKey [4]byte

func readPosition(r *Reader) error {
	if r.Header.CodeVersion < Y11S1 {
		return nil
	}

	// r.offset is 1 past the end of the 4-byte marker.
	// So marker occupied bytes [r.offset-4, r.offset).
	markerStart := r.offset - 4

	// Entity ID is at a fixed offset of -12 from marker start.
	entityOffset := markerStart - 12
	if entityOffset < 0 || entityOffset+4 > len(r.b) {
		return nil
	}
	var eid entityKey
	copy(eid[:], r.b[entityOffset:entityOffset+4])

	// Skip entities that don't look like game entities (byte[3] is always 0xf0)
	if eid[3] != 0xf0 {
		return nil
	}

	// Entity type counter is at entityOffset+8 (= markerStart-4).
	// Player entities have counter >= 400, drones/gadgets have < 250.
	typeCounterOffset := entityOffset + 8
	if typeCounterOffset+4 <= len(r.b) {
		typeCounter := binary.LittleEndian.Uint32(r.b[typeCounterOffset : typeCounterOffset+4])
		if typeCounter < 400 {
			return nil // drone or gadget entity
		}
	}

	// Read 2 flag bytes after the marker
	flagBytes, err := r.Bytes(2)
	if err != nil {
		return nil
	}
	flags0 := flagBytes[0]

	// Determine how many bytes to skip before XYZ based on first flag byte.
	// Discovered via binary analysis of 94k+ position markers:
	//   flags0 >= 0x80: XYZ immediately after flags (skip=0) — ~21k real positions
	//   flags0 in 0x40-0x7F: skip 3 bytes — ~1.8k real positions
	//   flags0 < 0x40: metadata/state packets, not reliable position data
	var coordSkip int
	switch {
	case flags0 >= 0x80:
		coordSkip = 0
	case flags0 >= 0x40:
		coordSkip = 3
	default:
		return nil // skip metadata packets that don't contain reliable XYZ
	}

	if err := r.Skip(coordSkip); err != nil {
		return nil
	}
	xBytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}
	yBytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}
	zBytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}

	x := math.Float32frombits(binary.LittleEndian.Uint32(xBytes))
	y := math.Float32frombits(binary.LittleEndian.Uint32(yBytes))
	z := math.Float32frombits(binary.LittleEndian.Uint32(zBytes))

	// Filter invalid positions
	if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) ||
		math.IsInf(float64(x), 0) || math.IsInf(float64(y), 0) || math.IsInf(float64(z), 0) {
		return nil
	}
	if x == 0 && y == 0 {
		return nil
	}
	if x < -500 || x > 500 || y < -500 || y > 500 || z < -500 || z > 500 {
		return nil
	}
	if z == -100 {
		return nil
	}

	pos := PlayerPosition{
		X:             x,
		Y:             y,
		Z:             z,
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
		offset:        r.offset,
	}

	if r.entityPositions == nil {
		r.entityPositions = make(map[entityKey][]PlayerPosition)
	}
	r.entityPositions[eid] = append(r.entityPositions[eid], pos)

	return nil
}

// buildEntityPlayerMap searches the binary for two entity mapping tables:
//   - Defender table: pattern `39 02 XX` with indexed entries
//   - Attacker table: pattern `21 02 ff` or `01 02` in offset order
//
// Players are mapped by sorting each team's DissectID byte[0] descending
// → entity table order.
func (r *Reader) buildEntityPlayerMap() map[entityKey]string {
	result := make(map[entityKey]string)
	if len(r.b) == 0 {
		return result
	}

	searchEnd := len(r.b) / 3
	if searchEnd > len(r.b) {
		searchEnd = len(r.b)
	}

	// === Find defender entity table ===
	// Pattern A: `3902 XX __ ff/01` [entity] [zeros] — indices 1+
	// Pattern B: `390a 00 01 ff` [8 hash bytes] [entity] [zeros] — index 0 (special)
	type indexedEntry struct {
		index    int
		entityID entityKey
		offset   int
	}
	var defEntries []indexedEntry
	for i := 0; i < searchEnd-16; i++ {
		if r.b[i] == 0x39 {
			if r.b[i+1] == 0x02 {
				// Standard entries: 39 02 XX __ ff/01 [entity]
				idx := int(r.b[i+2])
				if (r.b[i+4] == 0xff || r.b[i+4] == 0x01) && idx < 20 {
					var eid entityKey
					copy(eid[:], r.b[i+5:i+9])
					if eid[3] == 0xf0 && r.b[i+9] == 0 && r.b[i+10] == 0 && r.b[i+11] == 0 && r.b[i+12] == 0 {
						defEntries = append(defEntries, indexedEntry{index: idx, entityID: eid, offset: i})
					}
				}
			} else if r.b[i+1] == 0x0a && r.b[i+2] == 0x00 && r.b[i+3] == 0x01 && r.b[i+4] == 0xff {
				// Index 0 special: 39 0a 00 01 ff [8 bytes hash] [entity]
				var eid entityKey
				copy(eid[:], r.b[i+13:i+17])
				if eid[3] == 0xf0 {
					defEntries = append(defEntries, indexedEntry{index: 0, entityID: eid, offset: i})
				}
			}
		}
	}

	// === Find attacker entity table (pattern: `2102ff` or `0102` before [entityID] [zeros]) ===
	type offsetEntry struct {
		entityID entityKey
		offset   int
		isRecording bool // `0102` = recording player marker
	}
	var atkEntries []offsetEntry
	for i := 0; i < searchEnd-10; i++ {
		if i+7 < searchEnd && r.b[i+1] == 0x02 {
			if r.b[i] == 0x21 && r.b[i+2] == 0xff {
				// Standard: 21 02 ff [entity]
				var eid entityKey
				copy(eid[:], r.b[i+3:i+7])
				if eid[3] == 0xf0 && r.b[i+7] == 0 && r.b[i+8] == 0 && r.b[i+9] == 0 && r.b[i+10] == 0 {
					atkEntries = append(atkEntries, offsetEntry{entityID: eid, offset: i})
				}
			} else if r.b[i] == 0x01 {
				// Recording player: 01 02 [entity]
				var eid entityKey
				copy(eid[:], r.b[i+2:i+6])
				if eid[3] == 0xf0 && r.b[i+6] == 0 && r.b[i+7] == 0 && r.b[i+8] == 0 && r.b[i+9] == 0 {
					atkEntries = append(atkEntries, offsetEntry{entityID: eid, offset: i, isRecording: true})
				}
			}
		}
	}
	// Sort attacker entries by offset (matches header player order)
	sort.Slice(atkEntries, func(i, j int) bool {
		return atkEntries[i].offset < atkEntries[j].offset
	})

	// Deduplicate both tables
	defMap := make(map[int]entityKey)
	for _, e := range defEntries {
		defMap[e.index] = e.entityID
	}
	var atkUnique []entityKey
	atkSeen := make(map[entityKey]bool)
	for _, e := range atkEntries {
		if !atkSeen[e.entityID] {
			atkSeen[e.entityID] = true
			atkUnique = append(atkUnique, e.entityID)
		}
	}

	// Determine which team is defense and which is attack
	defTeamIdx := -1
	for i, t := range r.Header.Teams {
		if t.Role == Defense {
			defTeamIdx = i
			break
		}
	}

	// Split players by team — PRESERVE HEADER ORDER (entity table uses same order)
	var defPlayers, atkPlayers []Player
	for _, p := range r.Header.Players {
		if defTeamIdx >= 0 && p.TeamIndex == defTeamIdx {
			defPlayers = append(defPlayers, p)
		} else {
			atkPlayers = append(atkPlayers, p)
		}
	}

	// Build hash→player mapping. The 8-byte hash before each entity table
	// entry identifies the player. The first occurrence of each hash in the
	// file is near the player's header data, in header player order.
	type hashEntry struct {
		hash     [8]byte
		entityID entityKey
	}
	var allHashEntries []hashEntry

	// Collect hashes from DEF table
	for _, e := range defEntries {
		if e.offset >= 8 {
			var h [8]byte
			copy(h[:], r.b[e.offset-8:e.offset])
			allHashEntries = append(allHashEntries, hashEntry{hash: h, entityID: e.entityID})
		}
	}
	// Extended DEF format: `[8B hash] 39 0a XX 01 ff [4 zeros] [4 bytes] [entity]`
	// The hash is 8 bytes BEFORE `39 0a`. Entity is at offset+13 from `39`.
	// XX can be 00 (index 0 special), 01, 02, etc.
	for i := 8; i < searchEnd-20; i++ {
		if r.b[i] == 0x39 && r.b[i+1] == 0x0a && r.b[i+4] == 0xff {
			// Entity is at varying offset after marker. Try multiple positions.
			for _, entOff := range []int{13, 9, 5} {
				if i+entOff+4 >= searchEnd {
					continue
				}
				var eid entityKey
				copy(eid[:], r.b[i+entOff:i+entOff+4])
				if eid[3] == 0xf0 && eid[0] != 0 {
					var h [8]byte
					copy(h[:], r.b[i-8:i])
					allHashEntries = append(allHashEntries, hashEntry{hash: h, entityID: eid})
					break
				}
			}
		}
	}
	// Collect hashes from ATK table
	for _, e := range atkEntries {
		if e.offset >= 8 {
			var h [8]byte
			copy(h[:], r.b[e.offset-8:e.offset])
			allHashEntries = append(allHashEntries, hashEntry{hash: h, entityID: e.entityID})
		}
	}

	// For each hash, find its FIRST occurrence in the file and match to
	// the nearest player by file offset. Players are read in order, so
	// the first hash occurrence after a player's data belongs to that player.
	// Build player offset list from header order (approximate: evenly spaced in first 30%)
	playerOffsets := make([]struct {
		username string
		offset   int
	}, 0, len(r.Header.Players))
	// Find each player name in the binary to get their actual offset
	for _, p := range r.Header.Players {
		nameBytes := []byte(p.Username)
		off := bytes.Index(r.b[:searchEnd], nameBytes)
		if off >= 0 {
			playerOffsets = append(playerOffsets, struct {
				username string
				offset   int
			}{username: p.Username, offset: off})
		}
	}

	// Deduplicate hash entries (same hash may appear multiple times)
	hashToEntity := make(map[[8]byte]entityKey)
	for _, he := range allHashEntries {
		if _, exists := hashToEntity[he.hash]; !exists {
			hashToEntity[he.hash] = he.entityID
		}
	}
	log.Debug().Int("hashEntries", len(allHashEntries)).Int("uniqueHashes", len(hashToEntity)).Msg("hash_table_stats")

	// Each player's entity hash appears at a fixed delta (~1750-2000 bytes)
	// after their name in the file. Search at each player's name offset + delta
	// for any hash in the entity table.
	usedEntities := make(map[entityKey]bool)
	for _, p := range r.Header.Players {
		nameOff, ok := r.playerNameOffsets[p.Username]
		if !ok {
			continue
		}
		// Search window: name offset + 1700 to name offset + 2100
		windowStart := nameOff + 1700
		windowEnd := nameOff + 2100
		if windowStart >= len(r.b) || windowEnd > len(r.b) {
			continue
		}
		window := r.b[windowStart:windowEnd]
		for hash, eid := range hashToEntity {
			if bytes.Contains(window, hash[:]) {
				if usedEntities[eid] {
					log.Debug().
						Str("username", p.Username).
						Str("entity", fmt.Sprintf("%x", eid)).
						Str("claimedBy", result[eid]).
						Msg("binary_map_hash_conflict")
				} else {
					result[eid] = p.Username
					usedEntities[eid] = true
					log.Debug().
						Str("username", p.Username).
						Str("entity", fmt.Sprintf("%x", eid)).
						Msg("binary_map_hash")
				}
			}
		}
	}

	return result
}

// resolvePositionEntities maps entity IDs to player usernames after parsing.
// Match replays contain full position data for ALL players.
func (r *Reader) resolvePositionEntities() {
	if len(r.entityPositions) == 0 {
		return
	}

	r.PlayerPositions = make(map[string][]PlayerPosition)

	// Collect all entities and compute movement + last offset
	var allEntities []entityInfo
	for eid, positions := range r.entityPositions {
		if len(positions) < 10 {
			continue
		}
		var totalDist float64
		var maxOff int
		for j, p := range positions {
			if p.offset > maxOff {
				maxOff = p.offset
			}
			if j > 0 {
				dx := float64(p.X - positions[j-1].X)
				dy := float64(p.Y - positions[j-1].Y)
				d := math.Sqrt(dx*dx + dy*dy)
				if d < 10 {
					totalDist += d
				}
			}
		}
		allEntities = append(allEntities, entityInfo{
			key: eid, positions: positions, movement: totalDist, lastOffset: maxOff,
		})
	}

	numPlayers := len(r.Header.Players)

	// Use binary entity table mapping. Assign mapped players directly,
	// then fall through to heuristic matching for any unmapped players.
	binaryMap := r.buildEntityPlayerMap()
	mappedEntities := make(map[entityKey]bool)
	mappedPlayers := make(map[string]bool)

	// Check for Skopos
	skoposUser := ""
	for _, p := range r.Header.Players {
		rn := strings.ToUpper(p.RoleName)
		if rn == "SKOPOS" || p.Operator == Skopos {
			skoposUser = p.Username
		}
	}

	// Assign binary-mapped entities
	assigned := make(map[string]int) // username → count of entities assigned
	for eid, username := range binaryMap {
		if positions, ok := r.entityPositions[eid]; ok && len(positions) > 0 {
			if assigned[username] > 0 {
				// Skopos second entity
				r.PlayerPositions[username+" (2)"] = positions
			} else {
				r.PlayerPositions[username] = positions
			}
			assigned[username]++
			mappedEntities[eid] = true
			mappedPlayers[username] = true
		}
	}

	// Look for unmapped Skopos clone entity on defense site
	if skoposUser != "" && assigned[skoposUser] < 2 {
		if skoposPositions, ok := r.PlayerPositions[skoposUser]; ok && len(skoposPositions) > 0 {
			skoposZ := skoposPositions[0].Z
			bestClone := entityKey{}
			bestCloneCount := 0
			for eid, positions := range r.entityPositions {
				if mappedEntities[eid] || len(positions) < 10 {
					continue
				}
				if math.Abs(float64(positions[0].Z-skoposZ)) < 2 {
					if len(positions) > bestCloneCount {
						bestCloneCount = len(positions)
						bestClone = eid
					}
				}
			}
			if bestCloneCount > 0 {
				r.PlayerPositions[skoposUser+" (2)"] = r.entityPositions[bestClone]
				mappedEntities[bestClone] = true
				log.Debug().
					Str("entity", fmt.Sprintf("%x", bestClone)).
					Int("positions", bestCloneCount).
					Msg("skopos_second_entity")
			}
		}
	}

	// If all players mapped, we're done
	if len(mappedPlayers) >= numPlayers {
		r.interpolatePositionTimes()
		return
	}

	log.Debug().
		Int("mapped", len(mappedPlayers)).
		Int("total", numPlayers).
		Msg("partial_binary_map")

	// Filter out already-mapped entities and already-mapped players for heuristic fallback
	var unmappedEntities []entityInfo
	for _, e := range allEntities {
		if !mappedEntities[e.key] {
			unmappedEntities = append(unmappedEntities, e)
		}
	}
	allEntities = unmappedEntities

	var unmappedPlayerList []Player
	for _, p := range r.Header.Players {
		if !mappedPlayers[p.Username] {
			unmappedPlayerList = append(unmappedPlayerList, p)
		}
	}
	// Override numPlayers for heuristic matching
	numPlayers = len(unmappedPlayerList)
	if numPlayers == 0 {
		r.interpolatePositionTimes()
		return
	}
	// Temporarily replace Header.Players for heuristic matching
	origPlayers := r.Header.Players
	r.Header.Players = unmappedPlayerList
	defer func() { r.Header.Players = origPlayers }()

	// Sort by movement descending — top N are the unmapped players
	sort.Slice(allEntities, func(i, j int) bool {
		return allEntities[i].movement > allEntities[j].movement
	})

	// Check if Skopos is in the game — need one extra entity for the clone
	hasSkopos := false
	for _, p := range r.Header.Players {
		rn := strings.ToUpper(p.RoleName)
		if rn == "SKOPOS" || p.Operator == Skopos {
			hasSkopos = true
			break
		}
	}
	selectCount := numPlayers
	if hasSkopos && len(allEntities) > numPlayers {
		selectCount = numPlayers + 1
	}

	if numPlayers == 0 || len(allEntities) < numPlayers {
		return
	}
	playerEntities := allEntities[:selectCount]

	// If Skopos is present, the extra entity is the clone. The clone is
	// deployed on the defense site (same Z as other defenders). Among
	// entities starting at defender Z, the one with least movement is the clone.
	if hasSkopos && selectCount > numPlayers {
		skoposUser := ""
		for _, p := range r.Header.Players {
			rn := strings.ToUpper(p.RoleName)
			if rn == "SKOPOS" || p.Operator == Skopos {
				skoposUser = p.Username
				break
			}
		}
		if skoposUser != "" {
			// Find the most common starting Z among entities (= defense site Z)
			zCounts := make(map[int]int)
			for _, e := range playerEntities {
				if len(e.positions) > 0 {
					zBucket := int(e.positions[0].Z * 2) // bucket to nearest 0.5
					zCounts[zBucket]++
				}
			}
			siteZ := 0
			siteZCount := 0
			for z, cnt := range zCounts {
				if cnt > siteZCount {
					siteZCount = cnt
					siteZ = z
				}
			}

			// Among entities at site Z, find the one with least movement = clone
			cloneIdx := -1
			cloneMovement := math.MaxFloat64
			for i, e := range playerEntities {
				if len(e.positions) > 0 {
					zBucket := int(e.positions[0].Z * 2)
					if zBucket == siteZ && e.movement < cloneMovement {
						cloneMovement = e.movement
						cloneIdx = i
					}
				}
			}

			if cloneIdx >= 0 {
				cloneEntity := playerEntities[cloneIdx]
				// Store clone positions to merge with Skopos player later
				r.skoposClonePositions = cloneEntity.positions
				r.skoposUsername = skoposUser
				log.Debug().
					Str("username", skoposUser).
					Str("entity", fmt.Sprintf("%x", cloneEntity.key)).
					Int("positions", len(cloneEntity.positions)).
					Float64("movement", cloneEntity.movement).
					Msg("skopos_clone_detected")
				playerEntities = append(playerEntities[:cloneIdx], playerEntities[cloneIdx+1:]...)
			}
		}
	}

	// Get death times from MatchFeedback
	deathTimes := make(map[string]float64)
	for _, u := range r.MatchFeedback {
		if u.Type == Kill {
			deathTimes[u.Target] = u.TimeInSeconds
		} else if u.Type == Death {
			deathTimes[u.Username] = u.TimeInSeconds
		}
	}

	// Split players into defenders and attackers using team role from header
	defTeamIdx := -1
	for i, t := range r.Header.Teams {
		if t.Role == Defense {
			defTeamIdx = i
			break
		}
	}
	var defPlayers, atkPlayers []Player
	for _, p := range r.Header.Players {
		if defTeamIdx >= 0 && p.TeamIndex == defTeamIdx {
			defPlayers = append(defPlayers, p)
		} else {
			atkPlayers = append(atkPlayers, p)
		}
	}

	// Split entities into defenders and attackers by clustering first-position Z.
	// Defenders start on-site (indoors), attackers start outdoors.
	type zEntry struct {
		z   float32
		idx int
	}
	var zValues []zEntry
	for i, e := range playerEntities {
		if len(e.positions) > 0 {
			zValues = append(zValues, zEntry{z: e.positions[0].Z, idx: i})
		}
	}
	sort.Slice(zValues, func(i, j int) bool { return zValues[i].z < zValues[j].z })

	bestZGap := float32(0)
	bestZSplit := len(zValues) / 2
	for i := 1; i < len(zValues); i++ {
		gap := zValues[i].z - zValues[i-1].z
		if gap > bestZGap {
			bestZGap = gap
			bestZSplit = i
		}
	}

	lowZSet := make(map[int]bool)
	for i := 0; i < bestZSplit; i++ {
		lowZSet[zValues[i].idx] = true
	}

	// Match Z groups to teams. When team sizes differ, match by count.
	// When equal (5v5), defenders are on-site (indoors) and attackers spawn
	// outdoors. Outdoor spawn Z is typically 0-1 (ground level).
	// Indoor site Z varies by floor. Use the group whose average Z is
	// furthest from ground level (0) as defenders — they're on-site.
	lowCount := bestZSplit
	highCount := len(zValues) - bestZSplit
	lowIsDef := false
	if lowCount != highCount {
		// Unequal sizes: match by count
		lowIsDef = lowCount == len(defPlayers)
	} else {
		// Equal sizes: attackers start at ~ground level (z≈0-1),
		// defenders on-site at a different floor level.
		// The group with average Z closest to 0.5 = attackers.
		var avgLow, avgHigh float64
		for i := 0; i < bestZSplit; i++ {
			avgLow += float64(zValues[i].z)
		}
		avgLow /= float64(bestZSplit)
		for i := bestZSplit; i < len(zValues); i++ {
			avgHigh += float64(zValues[i].z)
		}
		avgHigh /= float64(len(zValues) - bestZSplit)
		// Group closer to ground level (0.5) = attackers
		lowDistToGround := math.Abs(avgLow - 0.5)
		highDistToGround := math.Abs(avgHigh - 0.5)
		lowIsDef = lowDistToGround > highDistToGround
	}

	var defEntities, atkEntities []entityInfo
	for i, e := range playerEntities {
		isLow := lowZSet[i]
		if (isLow && lowIsDef) || (!isLow && !lowIsDef) {
			defEntities = append(defEntities, e)
		} else {
			atkEntities = append(atkEntities, e)
		}
	}

	// Rebalance: if one group has too many entities, move excess to the other.
	for len(defEntities) > len(defPlayers) && len(atkEntities) < len(atkPlayers) {
		worstIdx := 0
		for i := 1; i < len(defEntities); i++ {
			if defEntities[i].movement < defEntities[worstIdx].movement {
				worstIdx = i
			}
		}
		atkEntities = append(atkEntities, defEntities[worstIdx])
		defEntities = append(defEntities[:worstIdx], defEntities[worstIdx+1:]...)
	}
	for len(atkEntities) > len(atkPlayers) && len(defEntities) < len(defPlayers) {
		worstIdx := 0
		for i := 1; i < len(atkEntities); i++ {
			if atkEntities[i].movement < atkEntities[worstIdx].movement {
				worstIdx = i
			}
		}
		defEntities = append(defEntities, atkEntities[worstIdx])
		atkEntities = append(atkEntities[:worstIdx], atkEntities[worstIdx+1:]...)
	}

	log.Debug().
		Int("defEntities", len(defEntities)).
		Int("atkEntities", len(atkEntities)).
		Int("defPlayers", len(defPlayers)).
		Int("atkPlayers", len(atkPlayers)).
		Float32("zGap", bestZGap).
		Msg("team_split")

	// Match defenders by death-time ↔ lastOffset (well-separated deaths)
	r.matchByDeathTime(defEntities, defPlayers, deathTimes)

	// Refine defender survivors using kill proximity
	r.interpolatePositionTimes()
	var defSurvivors []Player
	for _, p := range defPlayers {
		if _, hasDeath := deathTimes[p.Username]; !hasDeath {
			defSurvivors = append(defSurvivors, p)
		}
	}
	if len(defSurvivors) >= 2 {
		r.refineGroupByKills(defSurvivors)
	}

	// Match attackers by spawn group, then death-time within each group
	r.matchAttackersBySpawn(atkEntities, atkPlayers, deathTimes)
}

// matchByDeathTime matches entities to players using death-time ↔ lastOffset correlation.
func (r *Reader) matchByDeathTime(entities []entityInfo, players []Player, deathTimes map[string]float64) {
	if len(entities) == 0 || len(players) == 0 {
		return
	}

	// Sort entities by lastOffset ascending
	sort.Slice(entities, func(i, j int) bool {
		return entities[i].lastOffset < entities[j].lastOffset
	})

	type playerSorted struct {
		player   Player
		deathAt  float64
		hasDeath bool
	}
	var sorted []playerSorted
	for _, p := range players {
		dt, ok := deathTimes[p.Username]
		sorted = append(sorted, playerSorted{player: p, deathAt: dt, hasDeath: ok})
	}
	// Deaths first (DESCENDING time = earliest death), then survivors
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].hasDeath != sorted[j].hasDeath {
			return sorted[i].hasDeath
		}
		if sorted[i].hasDeath {
			return sorted[i].deathAt > sorted[j].deathAt
		}
		return false
	})

	n := len(sorted)
	if len(entities) < n {
		n = len(entities)
	}
	for i := 0; i < n; i++ {
		r.PlayerPositions[sorted[i].player.Username] = entities[i].positions
		log.Debug().
			Str("username", sorted[i].player.Username).
			Str("entity", fmt.Sprintf("%x", entities[i].key)).
			Int("positions", len(entities[i].positions)).
			Int("lastOffset", entities[i].lastOffset).
			Float64("deathAt", sorted[i].deathAt).
			Msg("entity_match_def")
	}
}

// matchAttackersBySpawn groups attackers by spawn name, clusters entities
// by first-position proximity, matches groups, then uses death-time within groups.
func (r *Reader) matchAttackersBySpawn(entities []entityInfo, players []Player, deathTimes map[string]float64) {
	if len(entities) == 0 || len(players) == 0 {
		return
	}

	// Group players by spawn. Treat "RANDOM", empty spawns, and
	// solo spawn groups as unknown — these players get matched after
	// multi-player spawn groups are resolved via death-time correlation.
	tempGroups := make(map[string][]Player)
	for _, p := range players {
		spawn := p.Spawn
		if spawn == "" || spawn == "RANDOM" {
			spawn = "_unknown"
		}
		tempGroups[spawn] = append(tempGroups[spawn], p)
	}
	// Only keep groups with 2+ players; merge singles into unknown pool
	spawnGroups := make(map[string][]Player)
	var unknownSpawnPlayers []Player
	for spawn, group := range tempGroups {
		if spawn == "_unknown" || len(group) < 2 {
			unknownSpawnPlayers = append(unknownSpawnPlayers, group...)
		} else {
			spawnGroups[spawn] = group
		}
	}

	// If only one spawn group (or none), fall back to death-time matching for all
	if len(spawnGroups) <= 1 && len(unknownSpawnPlayers) == 0 {
		r.matchByDeathTime(entities, players, deathTimes)
		return
	}
	if len(spawnGroups) == 0 {
		r.matchByDeathTime(entities, players, deathTimes)
		return
	}

	// Cluster entities by first position using k-means with k = number of spawn groups.
	// Simple approach: compute pairwise distances, find natural clusters.
	// For 2 spawn groups (most common), split by largest gap in X coordinate.
	type entWithPos struct {
		info entityInfo
		fx   float64
		fy   float64
	}
	var ents []entWithPos
	for _, e := range entities {
		fx, fy := float64(e.positions[0].X), float64(e.positions[0].Y)
		ents = append(ents, entWithPos{info: e, fx: fx, fy: fy})
	}

	// For each pair of spawn groups, compute centroid and assign entities
	// to the nearest centroid, respecting group sizes.
	spawnNames := make([]string, 0, len(spawnGroups))
	for name := range spawnGroups {
		spawnNames = append(spawnNames, name)
	}
	sort.Strings(spawnNames)

	// Compute k centroids using k-means initialization: pick entity closest to each spawn group size
	// Simple: sort entities by X, split according to group sizes
	sort.Slice(ents, func(i, j int) bool {
		return ents[i].fx < ents[j].fx
	})

	// Try all permutations of assigning sorted entity groups to spawn groups.
	// For 2 groups this is just 2 options; for 3+ we try the best distance match.
	type assignment struct {
		spawnName string
		entities  []entWithPos
		players   []Player
	}

	// Split sorted entities into groups matching spawn group sizes
	bestAssignment := make([]assignment, len(spawnNames))
	bestDist := math.MaxFloat64

	// Generate all permutations of spawn group ordering
	perms := permutations(len(spawnNames))
	for _, perm := range perms {
		var totalDist float64
		offset := 0
		valid := true
		for pi, si := range perm {
			sn := spawnNames[si]
			groupSize := len(spawnGroups[sn])
			if offset+groupSize > len(ents) {
				valid = false
				break
			}
			groupEnts := ents[offset : offset+groupSize]
			// Compute centroid of this entity group
			var cx, cy float64
			for _, e := range groupEnts {
				cx += e.fx
				cy += e.fy
			}
			cx /= float64(len(groupEnts))
			cy /= float64(len(groupEnts))
			// Compute spread (lower = tighter cluster = better)
			for _, e := range groupEnts {
				dx := e.fx - cx
				dy := e.fy - cy
				totalDist += math.Sqrt(dx*dx + dy*dy)
			}
			_ = pi
			offset += groupSize
		}
		if !valid {
			continue
		}
		if totalDist < bestDist {
			bestDist = totalDist
			offset = 0
			for pi, si := range perm {
				sn := spawnNames[si]
				groupSize := len(spawnGroups[sn])
				groupEnts := make([]entWithPos, groupSize)
				copy(groupEnts, ents[offset:offset+groupSize])
				bestAssignment[pi] = assignment{
					spawnName: sn,
					entities:  groupEnts,
					players:   spawnGroups[sn],
				}
				offset += groupSize
			}
		}
	}

	// Within each spawn group, match by death time
	for _, a := range bestAssignment {
		entInfos := make([]entityInfo, len(a.entities))
		for i, e := range a.entities {
			entInfos[i] = e.info
		}
		r.matchByDeathTime(entInfos, a.players, deathTimes)
		for _, p := range a.players {
			log.Debug().
				Str("username", p.Username).
				Str("spawn", a.spawnName).
				Msg("spawn_group_match")
		}
	}

	// Match unknown-spawn players with leftover entities via death-time
	if len(unknownSpawnPlayers) > 0 {
		// Find entities not yet assigned to any player
		assigned := make(map[entityKey]bool)
		for _, positions := range r.PlayerPositions {
			if len(positions) > 0 {
				var k entityKey
				// Match by first position offset
				for eid, ePositions := range r.entityPositions {
					if len(ePositions) > 0 && len(positions) > 0 &&
						ePositions[0].offset == positions[0].offset {
						k = eid
						break
					}
				}
				assigned[k] = true
			}
		}
		var leftoverEntities []entityInfo
		for _, e := range entities {
			if !assigned[e.key] {
				leftoverEntities = append(leftoverEntities, e)
			}
		}
		r.matchByDeathTime(leftoverEntities, unknownSpawnPlayers, deathTimes)
		for _, p := range unknownSpawnPlayers {
			log.Debug().
				Str("username", p.Username).
				Str("spawn", "UNKNOWN").
				Msg("spawn_group_match")
		}
	}

	// Merge Skopos clone positions into the player's array BEFORE time interpolation.
	if r.skoposUsername != "" && len(r.skoposClonePositions) > 0 {
		if existing, ok := r.PlayerPositions[r.skoposUsername]; ok {
			merged := append(existing, r.skoposClonePositions...)
			sort.Slice(merged, func(i, j int) bool {
				return merged[i].offset < merged[j].offset
			})
			r.PlayerPositions[r.skoposUsername] = merged
			log.Debug().
				Str("username", r.skoposUsername).
				Int("bodyPositions", len(existing)).
				Int("clonePositions", len(r.skoposClonePositions)).
				Int("merged", len(merged)).
				Msg("skopos_merged")
		}
	}

	// Interpolate time values before kill refinement so posAtTime works.
	r.interpolatePositionTimes()

	// Refine groups using kill proximity (both as killer and victim).
	// Apply to spawn groups with 2+ survivors AND the unknown pool.
	allGroups := make([][]Player, 0)
	for _, a := range bestAssignment {
		if len(a.players) >= 2 {
			var survivorPlayers []Player
			for _, p := range a.players {
				if _, hasDeath := deathTimes[p.Username]; !hasDeath {
					survivorPlayers = append(survivorPlayers, p)
				}
			}
			if len(survivorPlayers) >= 2 {
				allGroups = append(allGroups, survivorPlayers)
			}
		}
	}
	if len(unknownSpawnPlayers) >= 2 {
		// Only refine if there are 2+ survivors in the unknown pool
		unknownSurvivors := 0
		for _, p := range unknownSpawnPlayers {
			if _, hasDeath := deathTimes[p.Username]; !hasDeath {
				unknownSurvivors++
			}
		}
		if unknownSurvivors >= 2 {
			var survivorPool []Player
			for _, p := range unknownSpawnPlayers {
				if _, hasDeath := deathTimes[p.Username]; !hasDeath {
					survivorPool = append(survivorPool, p)
				}
			}
			allGroups = append(allGroups, survivorPool)
		}
	}
	for _, group := range allGroups {
		r.refineGroupByKills(group)
	}
}

// refineGroupByKills tries all permutations of position assignments within
// a group of players and picks the one that minimizes total distance from
// each killer to their victim at kill time.
func (r *Reader) refineGroupByKills(players []Player) {
	// Collect kill events where a player in this group is the killer OR victim
	groupSet := make(map[string]bool)
	for _, p := range players {
		groupSet[p.Username] = true
	}

	type killEvt struct {
		killer     string
		target     string
		timeRemain float64
		groupIsKiller bool // true if group player is killer, false if victim
	}
	var kills []killEvt
	for _, u := range r.MatchFeedback {
		if u.Type == Kill {
			if groupSet[u.Username] {
				kills = append(kills, killEvt{killer: u.Username, target: u.Target, timeRemain: u.TimeInSeconds, groupIsKiller: true})
			} else if groupSet[u.Target] {
				kills = append(kills, killEvt{killer: u.Username, target: u.Target, timeRemain: u.TimeInSeconds, groupIsKiller: false})
			}
		}
	}
	if len(kills) == 0 {
		return // no kills to differentiate
	}

	duration := r.maxTimeValue
	if duration <= 0 {
		duration = 180
	}

	// Collect current position slices for each player in the group
	usernames := make([]string, len(players))
	posSlices := make([][]PlayerPosition, len(players))
	for i, p := range players {
		usernames[i] = p.Username
		posSlices[i] = r.PlayerPositions[p.Username]
	}

	// Score a permutation: for each kill involving a group player,
	// measure distance between killer and victim at the kill moment.
	// When group player is killer: their last pos near victim's last pos.
	// When group player is victim: their last pos near killer's pos at kill time.
	scorePerm := func(perm []int) float64 {
		nameToPos := make(map[string][]PlayerPosition)
		for i, pi := range perm {
			nameToPos[usernames[i]] = posSlices[pi]
		}
		var totalDist float64
		for _, k := range kills {
			if k.groupIsKiller {
				// Group player is the killer — their last pos near victim's last pos
				kPositions := nameToPos[k.killer]
				tPositions := r.PlayerPositions[k.target]
				if len(kPositions) == 0 || len(tPositions) == 0 {
					continue
				}
				kLast := kPositions[len(kPositions)-1]
				tLast := tPositions[len(tPositions)-1]
				dx := float64(kLast.X - tLast.X)
				dy := float64(kLast.Y - tLast.Y)
				totalDist += math.Sqrt(dx*dx + dy*dy)
			} else {
				// Group player is the victim — their last pos near killer's position
				vPositions := nameToPos[k.target]
				kPositions := r.PlayerPositions[k.killer]
				if len(vPositions) == 0 || len(kPositions) == 0 {
					continue
				}
				vLast := vPositions[len(vPositions)-1]
				// Find killer's position closest to kill time
				killElapsed := duration - k.timeRemain
				bestIdx := 0
				bestDiff := math.Abs(kPositions[0].TimeInSeconds - killElapsed)
				for i, p := range kPositions {
					diff := math.Abs(p.TimeInSeconds - killElapsed)
					if diff < bestDiff {
						bestDiff = diff
						bestIdx = i
					}
				}
				kPos := kPositions[bestIdx]
				dx := float64(vLast.X - kPos.X)
				dy := float64(vLast.Y - kPos.Y)
				totalDist += math.Sqrt(dx*dx + dy*dy)
			}
		}
		return totalDist
	}

	// Try all permutations (max 5! = 120, usually 2-3 players)
	perms := permutations(len(players))
	bestScore := math.MaxFloat64
	bestPerm := perms[0]
	for _, perm := range perms {
		score := scorePerm(perm)
		if score < bestScore {
			bestScore = score
			bestPerm = perm
		}
	}

	// Check if best permutation differs from identity
	identity := true
	for i, pi := range bestPerm {
		if pi != i {
			identity = false
			break
		}
	}
	if identity {
		return
	}

	// Apply best permutation
	newPositions := make(map[string][]PlayerPosition)
	for i, pi := range bestPerm {
		newPositions[usernames[i]] = posSlices[pi]
	}
	for name, pos := range newPositions {
		r.PlayerPositions[name] = pos
	}
	log.Debug().
		Interface("permutation", bestPerm).
		Float64("score", bestScore).
		Msg("kill_perm_refine")
}

// permutations generates all permutations of indices [0..n-1]
func permutations(n int) [][]int {
	if n <= 0 {
		return [][]int{{}}
	}
	if n == 1 {
		return [][]int{{0}}
	}
	var result [][]int
	var helper func([]int, int)
	helper = func(arr []int, k int) {
		if k == 1 {
			tmp := make([]int, len(arr))
			copy(tmp, arr)
			result = append(result, tmp)
			return
		}
		for i := 0; i < k; i++ {
			helper(arr, k-1)
			if k%2 == 0 {
				arr[i], arr[k-1] = arr[k-1], arr[i]
			} else {
				arr[0], arr[k-1] = arr[k-1], arr[0]
			}
		}
	}
	arr := make([]int, n)
	for i := range arr {
		arr[i] = i
	}
	helper(arr, n)
	return result
}

// removed: refineBySpawn (replaced by matchAttackersBySpawn)

func (r *Reader) interpolatePositionTimes() {
	// Find global min/max offsets across all player positions
	minOff, maxOff := math.MaxInt64, 0
	for _, positions := range r.PlayerPositions {
		for _, p := range positions {
			if p.offset < minOff {
				minOff = p.offset
			}
			if p.offset > maxOff {
				maxOff = p.offset
			}
		}
	}
	if maxOff <= minOff {
		return
	}

	// Round duration from maxTimeValue (set by time markers),
	// or fall back to a default.
	duration := r.maxTimeValue
	if duration <= 0 {
		duration = 180 // 3 minutes default
	}

	offsetRange := float64(maxOff - minOff)
	for username, positions := range r.PlayerPositions {
		for i := range positions {
			frac := float64(positions[i].offset-minOff) / offsetRange
			// Time as elapsed seconds (0 = round start, duration = round end)
			elapsed := frac * duration
			remaining := duration - elapsed
			positions[i].TimeInSeconds = elapsed
			minutes := int(remaining) / 60
			seconds := int(remaining) % 60
			positions[i].Time = fmt.Sprintf("%d:%02d", minutes, seconds)
		}
		r.PlayerPositions[username] = positions
	}
}

// DedupPositions removes consecutive duplicate positions for each player
func DedupPositions(positions map[string][]PlayerPosition) map[string][]PlayerPosition {
	result := make(map[string][]PlayerPosition)
	for username, posSlice := range positions {
		if len(posSlice) == 0 {
			continue
		}
		// Filter any remaining NaN/Inf
		clean := make([]PlayerPosition, 0, len(posSlice))
		for _, p := range posSlice {
			if !math.IsNaN(float64(p.X)) && !math.IsNaN(float64(p.Y)) && !math.IsNaN(float64(p.Z)) &&
				!math.IsInf(float64(p.X), 0) && !math.IsInf(float64(p.Y), 0) && !math.IsInf(float64(p.Z), 0) {
				clean = append(clean, p)
			}
		}
		posSlice = clean
		if len(posSlice) == 0 {
			continue
		}
		deduped := []PlayerPosition{posSlice[0]}
		for i := 1; i < len(posSlice); i++ {
			prev := deduped[len(deduped)-1]
			curr := posSlice[i]
			// Keep if position changed by more than 0.05 units
			dx := float64(curr.X - prev.X)
			dy := float64(curr.Y - prev.Y)
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist > 0.05 {
				deduped = append(deduped, curr)
			}
		}
		result[username] = deduped
		log.Debug().
			Str("username", username).
			Int("raw", len(posSlice)).
			Int("deduped", len(deduped)).
			Msg("position_data")
	}
	return result
}
