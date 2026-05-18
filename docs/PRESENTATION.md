# Academic Presentation Outline

PowerPoint file:

```text
docs/SSH_WEB_FIREWALL_Academic_Presentation.pptx
```

Regenerate it with:

```bash
source .venv/bin/activate
python docs/create_presentation.py
```

## Slide Structure

1. **Title**
   - SSH/Web/Firewall Anomaly Detection With Live ELK Monitoring
   - Three model families, one reproducible architecture

2. **Problem Statement**
   - Security logs are heterogeneous and high-volume.
   - Labels are limited or noisy.
   - Operators need both offline evaluation and live monitoring.

3. **Research Objectives**
   - Build one architecture across Firewall, Web, and SSH data.
   - Train anomaly detectors on available public/security datasets.
   - Evaluate performance with reproducible figures.
   - Stream live logs and predictions into Kibana.

4. **System Architecture**
   - Data collection
   - Processing
   - Feature engineering
   - Isolation Forest training
   - Evaluation
   - Live scoring
   - Docker ELK visualization

5. **Datasets**
   - Firewall CSV with action labels.
   - NASA HTTP access logs.
   - SimpleWeb / University of Twente SSH Dataset 1.

6. **Feature Engineering**
   - Firewall row-level traffic rates and ratios.
   - Web per-host hourly access-window metrics.
   - SSH per-source-IP 10-minute authentication behavior.

7. **Modeling Method**
   - Isolation Forest for anomaly detection.
   - StandardScaler for numeric features.
   - Normal-baseline training where possible.

8. **Evaluation Protocol**
   - Firewall uses `Action` as ground truth.
   - Web uses `error_rate > 0.5` pseudo labels.
   - SSH uses behavior-rule pseudo labels.
   - Metrics: ROC-AUC, PR-AUC, confusion matrix, latency.

9. **Results Summary**
   - Firewall ROC-AUC 0.9686.
   - Web ROC-AUC 0.9855.
   - SSH ROC-AUC 0.9931.

10. **Firewall Results**
    - Confusion matrix.
    - ROC curve.
    - Feature/score correlation.

11. **Web Results**
    - Confusion matrix.
    - Precision-recall curve.
    - Feature/score correlation.

12. **SSH Results**
    - Confusion matrix.
    - ROC curve.
    - Feature/score correlation.

13. **Live Scoring**
    - Generator writes raw logs.
    - Listener tails files and scores with matching models.
    - Logstash tails raw and prediction files.

14. **Kibana Dashboard**
    - Prediction trend.
    - Prediction mix.
    - Average risk.
    - Raw log volume.
    - Firewall actions.
    - Web status outcomes.
    - SSH login status.

15. **Limitations**
    - Web/SSH use pseudo labels.
    - Isolation Forest is not an attack classifier.
    - Live demo generator is synthetic.

16. **Reproducibility**
    - Python venv.
    - Docker Compose ELK.
    - One command set to train/evaluate.
    - Multi-terminal live demo.

17. **Conclusion**
    - The project provides a practical baseline for multi-source anomaly detection with live visual monitoring.
