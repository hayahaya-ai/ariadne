package verdict

import (
	"sort"

	"github.com/hayahaya-ai/ariadne/ariadne-prove/internal/model"
)

var fleetVerdictOrder = []string{
	WordReckless,
	WordTradeoffsOnly,
	WordHardened,
	WordNoAgentsFound,
}

type fleetFamilyAccumulator struct {
	count   int
	targets map[string]bool
	reps    []fleetFindingRep
}

type fleetFindingRep struct {
	target  string
	finding RecklessFinding
}

// BuildFleet aggregates already-built ariadne.verdict/v1 endpoint verdicts.
// It does not inspect raw collection data or reinterpret attested controls.
func BuildFleet(verdicts []Verdict) model.FleetVerdictRollup {
	counts := map[string]int{}
	for _, word := range fleetVerdictOrder {
		counts[word] = 0
	}

	families := map[string]*fleetFamilyAccumulator{}
	targetRows := make([]model.FleetTargetVerdictRow, 0, len(verdicts))
	for _, v := range verdicts {
		counts[v.VerdictWord]++
		targetRows = append(targetRows, model.FleetTargetVerdictRow{
			Target:        v.Target,
			Verdict:       v.VerdictWord,
			RecklessCount: len(v.Reckless),
			TradeoffCount: len(v.Tradeoffs),
			HardenedCount: len(v.Hardened),
			Inconclusive:  v.Inconclusive,
		})
		for _, finding := range v.Reckless {
			acc := families[finding.ExposureID]
			if acc == nil {
				acc = &fleetFamilyAccumulator{targets: map[string]bool{}}
				families[finding.ExposureID] = acc
			}
			acc.count++
			acc.targets[v.Target] = true
			acc.reps = append(acc.reps, fleetFindingRep{target: v.Target, finding: finding})
		}
	}

	sort.SliceStable(targetRows, func(i, j int) bool {
		leftReckless := targetRows[i].RecklessCount > 0
		rightReckless := targetRows[j].RecklessCount > 0
		if leftReckless != rightReckless {
			return leftReckless
		}
		if targetRows[i].RecklessCount != targetRows[j].RecklessCount {
			return targetRows[i].RecklessCount > targetRows[j].RecklessCount
		}
		return targetRows[i].Target < targetRows[j].Target
	})

	familyKeys := make([]string, 0, len(families))
	for family := range families {
		familyKeys = append(familyKeys, family)
	}
	sort.Strings(familyKeys)

	byFamily := make([]model.FleetRecklessFamily, 0, len(familyKeys))
	for _, family := range familyKeys {
		acc := families[family]
		targets := make([]string, 0, len(acc.targets))
		for target := range acc.targets {
			targets = append(targets, target)
		}
		sort.Strings(targets)
		sort.SliceStable(acc.reps, func(i, j int) bool {
			if acc.reps[i].target == acc.reps[j].target {
				return acc.reps[i].finding.ID < acc.reps[j].finding.ID
			}
			return acc.reps[i].target < acc.reps[j].target
		})
		representative := model.FleetRepresentativeFinding{}
		if len(acc.reps) > 0 {
			representative = fleetRepresentativeFinding(acc.reps[0])
		}
		byFamily = append(byFamily, model.FleetRecklessFamily{
			Family:                family,
			Count:                 acc.count,
			AffectedTargets:       targets,
			RepresentativeFinding: representative,
		})
	}

	return model.FleetVerdictRollup{
		VerdictCounts:     counts,
		RecklessByFamily:  byFamily,
		WorstFirstTargets: targetRows,
	}
}

func fleetRepresentativeFinding(rep fleetFindingRep) model.FleetRepresentativeFinding {
	return model.FleetRepresentativeFinding{
		Target:     rep.target,
		FindingID:  rep.finding.ID,
		ExposureID: rep.finding.ExposureID,
		Title:      rep.finding.Title,
		Where: model.FleetEvidenceLocation{
			Source: rep.finding.Where.Source,
			Line:   rep.finding.Where.Line,
			Anchor: rep.finding.Where.Anchor,
		},
		Why: rep.finding.Why,
		Fix: rep.finding.Fix,
	}
}
