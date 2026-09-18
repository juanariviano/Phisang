# MarkupLM fine-tuning notebook

Fine-tunes `microsoft/markuplm-base` (token classification) on a toy HTML
dataset. Adapted from the [HuggingFace MarkupLM tutorial](https://github.com/NielsRogge/Transformers-Tutorials/blob/master/MarkupLM/Fine_tune_MarkupLMForTokenClassification_on_a_custom_dataset.ipynb)
for local (non-Colab) execution: the Colab-only cells (installing
`transformers` from git, `huggingface-cli login`, uploading a Google Drive
folder to the Hub) are commented out, since the toy dataset and base model
are both public and downloaded directly from the Hub.

Create and activate a project-local environment, then open the notebook:

```zsh
python3 -m venv ai/markuplm/.venv
ai/markuplm/.venv/bin/python -m pip install -r ai/markuplm/requirements-training.txt
ai/markuplm/.venv/bin/python -m ipykernel install --prefix ai/markuplm/.venv --name markuplm --display-name "MarkupLM (.venv)"
ai/markuplm/.venv/bin/jupyter-lab ai/markuplm/Fine_tune_MarkupLMForTokenClassification_on_a_custom_dataset.ipynb
```

The training loop picks `cuda` > `mps` (Apple Silicon) > `cpu` automatically.
