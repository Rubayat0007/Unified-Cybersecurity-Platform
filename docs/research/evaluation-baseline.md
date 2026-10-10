# Evaluation baseline audit (research branch)

## Scope and safeguards

This is a record of the initial evaluation-artifact audit for the unified cybersecurity platform. The original AI-NIDS and PhishVision-AI repositories, model files, production thresholds, and evaluation scripts are not modified by this audit. The reporting utility in `tools/evaluate_predictions.py` evaluates pre-existing CSV predictions; it does not train or load detector models.

## AI-NIDS: CICIDS2017

The primary documented evaluation uses a stratified 80/20 split with random state 42 and reports 404,127 held-out records. Its confusion matrix is `[[337409, 1188], [650, 64880]]`, with class 1 representing attacks. The recorded metrics are accuracy 99.5452%, precision 98.2019%, recall 99.0081%, and F1-score 98.6033%.

The inspected `src/train_cicids2017.py` and `src/evaluate_model.py` use the same data path, feature list, stratified split fraction, and random state. The training script fits the model on `X_train, y_train` and then saves the artifact and test metrics. The model artifact and primary metrics file timestamps are consistent with that script producing them. This supports, but does not independently prove, model lineage. The historical full-dataset evaluation is explicitly supplementary and must not be presented as held-out test performance.

The older `results/evaluation_predictions.csv` contains 2,000 rows and only `actual,predicted`; it is a separate artifact. Its recomputed confusion counts are TP=983, TN=976, FP=24, FN=17. Do not merge those results with the 404,127-row held-out report. The saved 2,000-row file has no probability column, so ROC AUC cannot be calculated from it.

## PhishVision-AI: v2 test probabilities

The saved `results/v2_test_probs_035.csv` has 85 records: 41 legitimate and 44 phishing. Recomputed at explicit threshold 0.35, with phishing as class 1, the confusion counts are TP=39, TN=16, FP=25, FN=5. Accuracy is 64.7059%, precision 60.9375%, recall 88.6364%, F1-score 72.2222%, specificity 39.0244%, and ROC AUC 0.694568.

`results/_final_validation_v2_test_probs_035.csv` is byte-identical to `v2_test_probs_035.csv`; it is not an independent evaluation.

### Robustness report threshold mismatch

The inspected `scripts/evaluate_robustness_v2.py` prints `THRESHOLD: 0.35`, but its `predict()` implementation sets the class prediction using `probabilities.argmax(dim=1)`. For this two-class softmax model, this is equivalent to choosing class 1 when its probability is at least 0.5 (ignoring exact ties), not 0.35. The evaluator records `p_phishing` but does not use 0.35 to generate its class prediction. This explains why the robustness CSV's clean baseline is 52/85 correct, with 23 correctly classified phishing images, while explicit 0.35 thresholding of the saved probabilities produces 55/85 correct.

At effective argmax threshold 0.5, the saved probabilities give TP=23, TN=29, FP=12, FN=21, accuracy 61.1765%, precision 65.7143%, recall 52.2727%, and F1-score 58.2278%. The original PhishVision files were not changed. Treat the printed 0.35 label as misleading until the original owners decide whether to update the evaluator/report.

## Interpretation limits

- The two detectors were evaluated on different datasets and different tasks. These separate results do not measure fusion performance.
- No ROC AUC should be inferred where prediction scores are unavailable.
- The small 85-image PhishVision test set produces uncertain estimates and should not be treated as a large-scale deployment guarantee.
- A valid learned-fusion study requires paired predictions from both sources for the same underlying labeled events, with clear split provenance and no test-set leakage.
