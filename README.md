# AI Projects

A collection of AI and machine learning projects spanning deep learning with TensorFlow, computer vision, natural language processing, time series forecasting, and production-grade AI security tooling.

Built by [Marius Poskus](https://mpcybersecurity.co.uk) — CISM, fractional CISO.

---

## Projects

### 🔒 Production AI

| Project | Description | Stack |
|---------|-------------|-------|
| [MP Cyber Security Advisor](./mcp-security-advisor/) | Autonomous AI security advisor — connects Claude to Defender XDR, Sentinel, Purview, Intune, Defender for Cloud, and M365 Admin Center. 28 tools with a risk engine that auto-remediates low-risk issues and escalates to Teams. | Python, FastMCP, Azure, Microsoft Graph API |

---

### 🧠 Deep Learning & Neural Networks

| Project | Description | Open in Colab |
|---------|-------------|---------------|
| [Neural Network Classification](./Neural_network_classification.ipynb) | Foundations of neural network classification — binary, multiclass, and multilabel problems built from scratch with TensorFlow/Keras | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/Neural_network_classification.ipynb) |
| [Convolutional Neural Networks](./03_Convolutional_Neural_Networks.ipynb) | Introduction to CNNs and computer vision with TensorFlow — pattern recognition in images, pooling, feature maps | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/03_Convolutional_Neural_Networks.ipynb) |
| [Image Classification — 20 Models](./Image_classification_project_20_models_improving_accuracy.ipynb) | Deep dive into image classification — trains and compares 20 model architectures, iteratively improving accuracy | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/Image_classification_project_20_models_improving_accuracy.ipynb) |

---

### 🔁 Transfer Learning Series

A three-part series exploring how to leverage pre-trained models (EfficientNet, ResNet, etc.) for custom tasks.

| Part | Project | Description | Open in Colab |
|------|---------|-------------|---------------|
| 1 | [Feature Extraction](./04_transfer_learning_1.ipynb) | Use a pre-trained model as a fixed feature extractor — freeze base layers, train only the classification head | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/04_transfer_learning_1.ipynb) |
| 2 | [Fine Tuning](./05_transfer_learning_02_fine_tuninig.ipynb) | Unfreeze deeper layers of the base model and fine-tune them on custom data for higher accuracy | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/05_transfer_learning_02_fine_tuninig.ipynb) |
| 3 | [Scaling Up](./06_transfer_learning_part_3.ipynb) | Scale the transfer learning pipeline — data augmentation, callbacks, mixed precision training | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/06_transfer_learning_part_3.ipynb) |

---

### 🍔 Milestone Projects

End-to-end projects applying the above techniques to real-world problems.

#### Food Vision
| Project | Description | Open in Colab |
|---------|-------------|---------------|
| [Food Vision Big](./07_Food_Vision_big.ipynb) | Large-scale food image classifier trained on the Food101 dataset (101 classes, 75,750 training images) using TensorFlow Datasets and EfficientNet — aims to beat the original paper's benchmark | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/07_Food_Vision_big.ipynb) |

#### SkimLit — Medical NLP
| Project | Description | Open in Colab |
|---------|-------------|---------------|
| [SkimLit](./09_SkimLit_project.ipynb) | NLP model to classify sentences in medical abstracts by role (Background, Methods, Results, Conclusions) — making research papers faster to skim. Trained on the PubMed 200k RCT dataset | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/09_SkimLit_project.ipynb) |

#### BitPredict — Time Series
| Project | Description | Open in Colab |
|---------|-------------|---------------|
| [Time Series Forecasting](./10_time_series_forecasting.ipynb) | Time series forecasting fundamentals with TensorFlow — windowing, naive models, dense networks, LSTMs, CNNs, and N-BEATS. Applied to Bitcoin price prediction (BitPredict) | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/10_time_series_forecasting.ipynb) |

---

### 💬 Natural Language Processing

| Project | Description | Open in Colab |
|---------|-------------|---------------|
| [NLP with TensorFlow](./08_Natural_language_processing.ipynb) | Fundamentals of NLP — text tokenisation, embeddings, RNNs, LSTMs, GRUs, and Conv1D models for text classification | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Kuizinass/AI-Projects/blob/main/08_Natural_language_processing.ipynb) |

---

## Featured Project: MP Cyber Security Advisor

The most recent project in this repo takes a different direction — moving from learning notebooks into a **production-deployed AI system**.

The [MP Cyber Security Advisor](./mcp-security-advisor/) is a **Model Context Protocol (MCP) server** hosted on Azure that gives Claude AI direct access to the full Microsoft security stack. Instead of manually checking five different security portals, you talk to Claude and it queries, analyses, and acts across your environment in a single conversation.

**What it connects to:**
- Microsoft Defender XDR — incidents, alerts, advanced hunting, CVEs
- Microsoft Sentinel — incidents, KQL queries, analytic rules
- Microsoft Defender for Cloud — recommendations, compliance posture
- Microsoft Intune — device compliance, configuration policies
- Microsoft Purview — DLP alerts, sensitivity labels
- M365 Admin Center — MFA status, Conditional Access, tenant settings
- Microsoft Secure Score — controls and improvement opportunities

**Risk engine:**

Every action the AI proposes goes through a scored risk gate before anything is executed:

| Score | Level | What happens |
|-------|-------|-------------|
| 0–30 | LOW | Auto-executed immediately |
| 31–70 | MEDIUM | Teams approval card sent to analyst |
| 71–100 | HIGH / CRITICAL | Escalated to analyst, never executed |

**Example conversations with Claude:**
> *"What is our Secure Score and what are the top 5 controls to fix first?"*

> *"Are there any High severity incidents open in Defender XDR right now?"*

> *"Check MFA status — which admins don't have MFA registered?"*

> *"Run a KQL query in Sentinel for failed logins from outside the UK in the last 24 hours."*

→ [Full documentation and deployment guide](./mcp-security-advisor/README.md)

---

## Tech Stack Summary

| Area | Technologies |
|------|-------------|
| Deep Learning | TensorFlow 2.x, Keras, EfficientNet, ResNet |
| Computer Vision | CNNs, Transfer Learning, TensorFlow Datasets, Food101 |
| NLP | Text embeddings, RNNs, LSTMs, Conv1D, PubMed 200k RCT |
| Time Series | Windowing, N-BEATS, LSTMs, Bitcoin price data |
| Production AI | Python, FastMCP, Azure Container Apps, Microsoft Graph API |
| Infrastructure | Azure Bicep, Managed Identity, Key Vault, Sentinel |
| Development | Google Colab, Jupyter, pytest |

---

## About

**Marius Poskus** — CISM, vCISO / Fractional CISO

- Website: [mpcybersecurity.co.uk](https://mpcybersecurity.co.uk)
- Email: mp@mpcybersecurity.co.uk
- Services: Security strategy, risk management, compliance (FCA/DORA/ISO 27001), vCISO for SMBs and scale-ups
