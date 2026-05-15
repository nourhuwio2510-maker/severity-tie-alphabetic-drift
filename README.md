# Severity-Tie Alphabetic Drift in SCA Vulnerability Ranking

This repository contains the proof-of-concept implementation for the paper:

**Beyond Severity: Measuring and Correcting Ranking Failures in Software Composition Analysis Tools Through Context-Aware Scoring**

## Overview

Modern software projects depend heavily on third-party and open-source packages. Software Composition Analysis (SCA) tools help identify vulnerable dependencies, but they often produce many findings that must be prioritized.

This project investigates a ranking failure mode called **severity-tie alphabetic drift**. This occurs when multiple vulnerability findings share the same severity level and the scanner falls back to alphabetic package ordering as an implicit tie-breaker. Under this condition, unreachable or less relevant packages may appear above reachable components used in critical application functionality.

The proposed framework corrects this issue using a context-aware risk score based on:

- Severity
- Reachability
- Exploitability
- Component criticality

## Proof-of-Concept Summary

The proof-of-concept uses a small Python web application with:

- 5 direct dependencies
- 9 transitive dependencies
- 14 SBOM components
- 107 matched OSV vulnerability findings
- 48 direct dependency findings
- 59 transitive dependency findings
- Uniform Medium severity across all findings

## Main Result

At the main evaluation cutoff, K = 29:

| Method | Precision@29 | Recall@29 |
|---|---:|---:|
| OSV-Scanner v2 baseline | 34.5% | 34.5% |
| Proposed framework | 100.0% | 100.0% |

The framework also reduces the urgent queue from 107 findings to 12 findings under the strict reachability threshold R >= 6.

## Repository Structure

```text
demo_app/      Controlled Python web application used in the proof-of-concept
outputs/       Generated CSV outputs from the framework
figures/       Figures used in the paper
data/          Dataset source information
main.py        Main implementation script
main.ipynb     Notebook version of the implementation
```

## Dataset

The vulnerability records are derived from the public Kaggle dataset:

**Open Source Cyber Debt: The Contagion Graph**

Kaggle identifier:

```text
kanchana1990/open-source-cyber-debt-the-contagion-graph
```

The dataset is based on vulnerability records from Google's OSV.dev database.

The dataset was used to match vulnerability records against the generated SBOM components in the proof-of-concept evaluation. The full dataset is not stored directly in this repository. Instead, the implementation downloads or references the public Kaggle dataset, and the generated outputs used in the paper are provided in the `outputs/` folder.

## Risk Scoring Model

The framework computes a composite risk score:

```text
Risk Score = (0.40S + 0.25R + 0.20E + 0.15C) × 10
```

Where:

- S = Severity
- R = Reachability
- E = Exploitability
- C = Component criticality

## Generated Outputs

The `outputs/` folder contains the generated CSV files used in the evaluation:

```text
sbom.csv
package_usage.csv
risk_aware_findings.csv
comparison_summary.csv
precision_recall_at_k.csv
package_level_risk_scores.csv
top_10_prioritized_findings.csv
```

The `figures/` folder contains the figures used in the paper:

```text
dependency_graph_bw_rectangles.png
precision_at_k_comparison.png
recall_at_k_comparison.png
final_risk_under_uniform_severity.png
reachability_distribution.png
```

## Reproducibility

To reproduce the experiment:

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the script:

```bash
python main.py
```

3. Review generated outputs in:

```text
outputs/
figures/
```

## Notes

This is a controlled proof-of-concept implementation. The reachability analysis uses static import usage as a lightweight proxy. Future work should extend this implementation with full call-graph reachability analysis and larger multi-project evaluation.
