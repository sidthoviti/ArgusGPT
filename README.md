# ArgusGPT
### Threat Modeling Using DeepSeek-R1 and RAG

A tool for generating threat models and attack trees from system documentation using Large Language Models (LLMs) and Retrieval Augmented Generation (RAG).

Read the detailed blog post here. ([https://sidthoviti.com/threat-modeling-using-llm/])

## Overview

ArgusGPT leverages the power of LLMs, specifically  DeepSeek-R1, combined with a RAG pipeline to analyze system documentation (e.g., Product Requirement Documents - PRDs) and generate structured threat models and attack trees. This helps security engineers quickly identify potential vulnerabilities and visualize attack paths.

## Features

*   Automated Threat Modeling: Extracts security threats, classifies them, maps them to common vulnerability categories (e.g., OWASP Top 10), and suggests remediation strategies.
*   Attack Tree Generation: Creates visual attack trees using Mermaid.js syntax to model attack paths and prioritize risks.
*   Document Processing: Handles PDF documents, extracts text, and uses semantic chunking for efficient retrieval.
*   Customizable Prompts:  Allows for tailoring the LLM's analysis through prompt engineering.
*   Streamlit Interface: Provides a user-friendly web interface for uploading documents, configuring analysis parameters, and viewing results.

## Getting Started

### Prerequisites

*   Python 3.7+
*   Ollama (for running the DeepSeek-R1 LLM) - Follow the Ollama installation instructions for your system. Ensure DeepSeek-R1 is available to Ollama.
*   A suitable PDF document (e.g., a PRD) for analysis.

### Installation

1.  Clone the repository:

    ```bash
    git clone [https://github.com/sidthoviti/ArgusGPT.git](https://www.google.com/search?q=https://github.com/sidthoviti/ArgusGPT.git)
    cd ArgusGPT
    ```

2.  Create a virtual environment (recommended):

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  Install the required packages:

    ```bash
    pip install -r requirements.txt
    ```

### Usage

1.  Run the Streamlit application:

    ```bash
    streamlit run app.py
    ```

2.  Open the application in your web browser (usually at `http://localhost:8501`).

3.  Upload your PDF document.

4.  Select the application type, authentication method, platform description, and internet exposure.

5.  The threat model will be generated automatically.

6.  Click "Create Attack Tree" to generate the attack tree visualization.

7.  View the generated threat model and attack tree.  Download the threat model report if needed.

## Requirements
streamlit
langchain
langchain_community
langchain_experimental
pdfplumber
faiss-cpu  # Use faiss-gpu if you have a compatible GPU
huggingface_hub
transformers
sentence_transformers
regex

## Future Development

*   Context-aware chat: Allow users to interactively query the threat model.
*   Multi-agent LLMs: Implement specialized LLM agents for different tasks.
*   Automated DFD generation: Integrate Data Flow Diagram generation with trust boundary mapping.
*   Integrate more Frameworks: Frameworks like DREAD, PASTA may also be integrated.
*   Improved Mermaid.js rendering: Direct graph visualization within the Streamlit app.
*   Support for other LLMs:  Make the LLM selection configurable.
