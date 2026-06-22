# Detection scorecard

- Rules: 7
- Verdicts: 3 keep, 2 tune, 2 retire
- Portfolio precision proxy: 0.67
- ATT&CK: 3 techniques, 71% of rules tagged

## Retire (2)

| Rule | Level | Precision | Volume | FP | ATT&CK | Reason |
|---|---|---|---|---|---|---|
| Dead Rule | medium | - | 0 | 0 | T1059 | no fires across the backtest corpus and the metrics window (dead rule) |
| Retire Noisy | low | 0.00 | 5 | 5 | T1110 | precision proxy 0.00 below the 0.10 retire floor |

## Tune (2)

| Rule | Level | Precision | Volume | FP | ATT&CK | Reason |
|---|---|---|---|---|---|---|
| Live Noisy | medium | 1.00 | 60 | 0 | T1110 | live false-positive ratio 0.80 exceeds the 0.50 ceiling |
| Sole Cover | high | 0.00 | 4 | 4 | T1003 | precision proxy 0.00 below the 0.10 retire floor; retained as the sole ATT&CK coverage (T1003), tune rather than retire |

## Keep (3)

| Rule | Level | Precision | Volume | FP | ATT&CK | Reason |
|---|---|---|---|---|---|---|
| Dup Title | low | 1.00 | 15 | 0 | - | precision proxy 1.00 at or above the 0.80 keep floor and firing within the window |
| Dup Title | low | 1.00 | 15 | 0 | - | precision proxy 1.00 at or above the 0.80 keep floor and firing within the window |
| Keep Rule | high | 1.00 | 110 | 0 | T1059 | precision proxy 1.00 at or above the 0.80 keep floor and firing within the window |
