import streamlit as st
from langchain_community.document_loaders import PDFPlumberLoader
from langchain_experimental.text_splitter import SemanticChunker
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains.llm import LLMChain
from langchain.chains.combine_documents.stuff import StuffDocumentsChain
from langchain.chains import RetrievalQA
import re

def filter_think_tags(content):
    """Extracts and removes <think> tags from content, displaying their content in a dropdown."""
    think_matches = re.findall(r'<think>(.*?)</think>', content, re.DOTALL)
    filtered_content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
    return filtered_content.strip(), think_matches

def extract_mermaid_code(content):
    """Extracts only the Mermaid syntax code block from LLM response."""
    match = re.search(r'```mermaid\n(.*?)\n```', content, re.DOTALL)
    return match.group(1) if match else content

def generate_threat_model_prompt(app_type, auth_method, platform, is_internet_facing):
    """Generates a prompt for the LLM to analyze security threats using STRIDE methodology."""
    prompt = f"""
    You are an experienced Security Architect specializing in STRIDE Threat Modeling. 
    Analyze security threats for the given **System Context** and **Document Context**, 
    strictly following the structure below.

    ## **System Context:**
    - **Application Type:** {app_type}
    - **Authentication Method:** {auth_method}
    - **Platform:** {platform}
    - **Internet Facing:** {is_internet_facing}

    ## **Document Context:**
    {{context}}

    ## **Instructions:**
    - **Strictly follow the output format below.**
    - Do not provide explanations, summaries, or general security recommendations.
    - Identify and analyze **each asset/component** against **all STRIDE categories** only.
    - **Allowed STRIDE categories:**
      - **Spoofing**
      - **Tampering**
      - **Repudiation**
      - **Information Disclosure**
      - **Denial of Service**
      - **Elevation of Privilege**
    - **Only use the following OWASP Top 10 (2021) categories for mapping threats:**
      - **A01: Broken Access Control**
      - **A02: Cryptographic Failures**
      - **A03: Injection**
      - **A04: Insecure Design**
      - **A05: Security Misconfiguration**
      - **A06: Vulnerable and Outdated Components**
      - **A07: Identification and Authentication Failures**
      - **A08: Software and Data Integrity Failures**
      - **A09: Security Logging and Monitoring Failures**
      - **A10: Server-Side Request Forgery (SSRF)**
    - Consider **trust boundaries, data flows, and deployment model** in the threat assessment.
    - Provide **specific and actionable remediation steps**.
    - **Return the Asset Analysis Table in valid Markdown format.**

    ## **Asset Threat Model Table Format (Markdown)**
    | Asset/Component | STRIDE Category | Threat Description | Impact | Trust Boundary Breach | OWASP Mapping | Remediation |
    |----------------|----------------|---------------------|--------|----------------------|---------------|-------------|
    | Example Asset | Spoofing | Unauthorized access using weak authentication | High | Yes | A1: Broken Access Control | Enforce MFA and strong authentication |
    
    ## **Additional Threat Analysis Sections (After Table)**
    After the table, include the following structured threat analysis:

    ### **Trust Boundaries**
    - Identify and list all trust boundaries.
    - Define security implications of trust boundaries breached.

    ### **Data Flows**
    - Map all data flows between components.
    - Indicate which data flows cross trust boundaries.

    ### **Deployment Threat Model**
    - Identify risks related to the deployment environment.
    - Consider multi-cloud, on-premises, or hybrid deployments.
    - Assess threats based on network exposure, CI/CD security, and container security.

    ### **Build Threat Model**
    - Analyze the security of the build and release process.
    - Include risks related to CI/CD pipelines, supply chain security, and software dependencies.

    ### **Assumptions & Open Questions**
    - List assumptions made in the threat model.
    - Highlight areas requiring further security validation.

    **Ensure that the Markdown table is correctly formatted and followed by structured analysis as defined above.** 
    """
    return prompt

def generate_attack_tree_prompt(threat_model_output, document_context):
    """Generates a detailed attack tree in Mermaid syntax using structured attack methodology."""
    prompt = f"""
    Act as a cybersecurity expert with more than 20 years of experience in STRIDE threat modeling.
    Using the following threat model analysis and document context, generate an **attack tree** in **valid Mermaid syntax**.  **Return ONLY the Mermaid code block. Do not include any explanatory text or descriptions.**

    ## **Threat Model Analysis**
    {threat_model_output}

    ## **Document Context**
    {document_context}

    ## **Instructions**
    - Clearly define the **Root Goal** of the attack.
    - Identify **High-Level Attack Paths (Sub-Goals)** an attacker might use.
    - Expand **each attack path** with detailed steps, considering:
      - Code Injection
      - Exploiting vulnerabilities
      - Supply chain attacks
      - Misconfigurations
    - Apply **Logical Operators**:
      - `[AND]` = All conditions must be met.
      - `[OR]` = Any one condition is sufficient.  *(Note:  The LLM may struggle with complex AND/OR logic in Mermaid.  Start simple and iterate.)*
    - Assign **Attributes** to each node (as Mermaid node text or tooltips - see example):
      - **Likelihood** (Low/Medium/High)
      - **Impact** (Low/Medium/High)
      - **Effort** (Low/Medium/High)
      - **Skill Level** (Low/Medium/High)
      - **Detection Difficulty** (Easy/Moderate/Hard)
    - **Output Format:** Return *only* a valid Mermaid code block, enclosed in triple backticks.  **Do not include any other text.**

    ## **Attack Tree Format**
    ```mermaid
    graph TD;
        A[Root Goal: Compromise Application] -->|Path 1| B[Exploit Known Vulnerability<br>Likelihood: High<br>Impact: High];
        A -->|Path 2| C[Inject Malicious Code<br>Likelihood: Medium<br>Impact: Critical];

        B -->|Step 1| B1[Find Vulnerable Component<br>Effort: Low<br>Skill: Low];
        B1 -->|Step 2| B2[Exploit via Remote Code Execution<br>Effort: Medium<br>Skill: Medium];
        B2 -->|Step 3| B3[Gain Unauthorized Access<br>Effort: High<br>Skill: High];

        C -->|Step 1| C1[Identify Injection Point<br>Effort: Medium<br>Skill: Medium];
        C1 -->|Step 2| C2[Insert Malicious Payload<br>Effort: High<br>Skill: High];
        C2 -->|Step 3| C3[Execute Arbitrary Code<br>Effort: High<br>Skill: High];

        classDef critical fill:#ff4d4d,stroke:#000;
        classDef high fill:#ff751a,stroke:#000;
        classDef medium fill:#ffcc00,stroke:#000;
        classDef low fill:#66ccff,stroke:#000;

        B3:::critical;
        C3:::high;
    ```
    """
    return prompt

def generate_threat_model(docs, app_type, auth_method, platform, is_internet_facing):
    """Generates a threat model using the provided documents and system context."""
    embedder = HuggingFaceEmbeddings()
    text_splitter = SemanticChunker(embedder)
    documents = text_splitter.split_documents(docs)
    vector = FAISS.from_documents(documents, embedder)
    retriever = vector.as_retriever(search_type="similarity", search_kwargs={"k": 5})
    llm = Ollama(model="deepseek-r1")
    
    threat_model_prompt = generate_threat_model_prompt(app_type, auth_method, platform, is_internet_facing)
    QA_PROMPT = PromptTemplate.from_template(threat_model_prompt)
    llm_chain = LLMChain(llm=llm, prompt=QA_PROMPT)
    combine_documents_chain = StuffDocumentsChain(llm_chain=llm_chain, document_variable_name="context")
    qa = RetrievalQA(combine_documents_chain=combine_documents_chain, retriever=retriever)
    
    return qa({"query": "Generate a threat model based on the provided document and details."})["result"]

def generate_attack_tree(threat_model_output, document_context):
    """Generates an attack tree using the threat model output and document context."""
    llm = Ollama(model="deepseek-r1")
    attack_tree_prompt = generate_attack_tree_prompt(threat_model_output, document_context)
    attack_tree_response = llm(attack_tree_prompt)
    return attack_tree_response

# Initialize Streamlit app
st.set_page_config(page_title="ArgusGPT", layout="wide")
st.title("ArgusGPT - Threat Modeling & Attack Trees")

# Initialize session state variables
if "app_state" not in st.session_state:
    st.session_state.app_state = {
        "threat_model_output": None,
        "attack_tree_output": None,
        "document_context": None,
        "threat_model_generated": False,
        "attack_tree_generated": False,
    }

app_state = st.session_state.app_state

# Sidebar description
st.sidebar.title("ArgusGPT")
st.sidebar.markdown("""
**Usage Instructions:**
1. Select application details.
2. Upload a PRD document (PDF).
3. Threat Model will be generated automatically.
4. Click **Create Attack Tree** to visualize attack paths.
""")

st.header("Threat Modeling with DeepSeek-R1 and RAG")

# User inputs
app_type = st.selectbox("Application Type", ["Web", "Mobile", "API", "Desktop"], index=0)
auth_method = st.selectbox("Authentication Method", ["OAuth", "JWT", "Session-based", "API Key", "Basic"], index=0)
platform = st.text_input("Describe the Application", "")
is_internet_facing = st.radio("Is the application internet-facing?", ["Yes", "No"], index=0)

# File uploader
uploaded_file = st.file_uploader("Upload PRD Document (PDF)", type=["pdf"])

# Main content area
main_container = st.container()

with main_container:
    if uploaded_file:
        # Process document
        with open("temp.pdf", "wb") as f:
            f.write(uploaded_file.getvalue())
        
        loader = PDFPlumberLoader("temp.pdf")
        docs = loader.load()
        app_state["document_context"] = "\n".join([doc.page_content for doc in docs])
        
        # Auto-generate threat model
        if not app_state["threat_model_generated"]:
            with st.spinner("Generating Threat Model..."):
                try:
                    threat_model = generate_threat_model(docs, app_type, auth_method, platform, is_internet_facing)
                    app_state["threat_model_output"] = threat_model
                    app_state["threat_model_generated"] = True
                except Exception as e:
                    st.error(f"Error generating threat model: {str(e)}")
            st.rerun()
        
        # Display threat model output
        if app_state["threat_model_output"]:
            filtered_output, think_contents = filter_think_tags(app_state["threat_model_output"])
            
            st.markdown("### Threat Model Response")
            st.markdown(filtered_output)
            
            if think_contents:
                with st.expander("Reasoning (LLM Insights)"):
                    for think in think_contents:
                        st.markdown(f"- {think}")
            
            st.download_button(
                label="Download Threat Model Report",
                data=filtered_output,
                file_name="threat_model.md",
                mime="text/markdown"
            )
            
            # Attack Tree Generation
            if st.button("Create Attack Tree") and not app_state["attack_tree_generated"]:
                with st.spinner("Creating Attack Tree..."):
                    try:
                        attack_tree_response = generate_attack_tree(
                            app_state["threat_model_output"],
                            app_state["document_context"]
                        )
                        filtered_attack_tree, tree_think_contents = filter_think_tags(attack_tree_response)
                        mermaid_code = extract_mermaid_code(filtered_attack_tree)
                        app_state["attack_tree_output"] = mermaid_code
                        app_state["attack_tree_generated"] = True
                    except Exception as e:
                        st.error(f"Error generating attack tree: {str(e)}")
                st.rerun()
            
            # Display attack tree if available
            if app_state["attack_tree_output"]:
                st.markdown("### Attack Tree (Mermaid Syntax)")
                st.code(f"""```mermaid\n{app_state["attack_tree_output"]}\n```""", language="mermaid")
