# MarkupLM fine-tuning notebook

`Fine_tune_MarkupLMForTokenClassification_on_a_custom_dataset.ipynb` fine-tunes
`microsoft/markuplm-base` (`MarkupLMForSequenceClassification`, one label per page)
on the same PhreshPhish split as `finetune_laya_phishing_kaggle_v2.ipynb`: 5,000
training, 1,000 validation and 1,000 test pages per class. The sampling cell is a
verbatim copy of Laya's, so the two models can be compared like for like. The file
name is historical; it used to hold the HuggingFace token-classification tutorial.

Run it on a Kaggle GPU (Settings → Accelerator → GPU), then download the
`markuplm-phishing-5k` output folder to `ai/markuplm/artifacts/` and score it on the
300 Mendeley pages with `smoke_test.ipynb`.

Set `LAYA_ARTIFACT_DIR` in the configuration cell to the Laya artifact (attached as a
Kaggle input) to check that both models were tested on identical pages and to print
their test AUCs side by side.
