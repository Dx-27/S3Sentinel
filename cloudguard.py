# CloudGuard Analyzer

# Imports
import streamlit as st
import boto3
import pandas as pd
from botocore.exceptions import ClientError
from fpdf import FPDF
from datetime import datetime

# Page config and layout
st.set_page_config(page_title="CloudGuard | S3 Security Scanner", page_icon="☁️", layout="wide")

# Styling (CSS)
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #FAFAFA; }
    .risk-high { color: #FF4B4B; font-weight: bold; }
    .risk-safe { color: #00FF00; font-weight: bold; }
    .metric-card { background-color: #262730; padding: 15px; border-radius: 8px; border-left: 4px solid #FF4B4B; }
    </style>
""", unsafe_allow_html=True)

# PDF report generator
def generate_pdf(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    
    pdf.cell(200, 10, txt="CloudGuard Security Audit Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)
    
    at_risk = len([r for r in results if r['Status'] == 'DANGER'])
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, txt=f"Executive Summary: Found {at_risk} At-Risk Buckets", ln=True)
    pdf.ln(5)
    
    pdf.set_font("Arial", size=10)
    for res in results:
        status_color = "CRITICAL" if res['Status'] == 'DANGER' else "SAFE"
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(0, 8, txt=f"Bucket: {res['Name']} [{status_color}]", ln=True)
        
        pdf.set_font("Arial", size=9)
        pdf.cell(0, 5, txt=f" - Public Access Block: {res['PublicAccessBlock']}", ln=True)
        pdf.cell(0, 5, txt=f" - Encryption: {res['Encryption']}", ln=True)
        pdf.cell(0, 5, txt=f" - Versioning: {res['Versioning']}", ln=True)
        pdf.ln(3)
        
    pdf.output("CloudGuard_Report.pdf")
    return "CloudGuard_Report.pdf"

# AWS scanning logic (bucket checks)
def scan_bucket(s3_client, bucket_name):
    """Scans a single bucket for 3 key security metrics."""
    risk_score = 0
    issues = []
    
    public_status = "Unknown"
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        conf = pab['PublicAccessBlockConfiguration']
        if conf['BlockPublicAcls'] and conf['BlockPublicPolicy']:
            public_status = "✅ Locked (Private)"
        else:
            public_status = "❌ Publicly Accessible"
            risk_score += 50
    except ClientError:
        public_status = "⚠️ Not Configured (Potentially Public)"
        risk_score += 30

    encryption = "❌ Disabled"
    try:
        enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
        encryption = "✅ Enabled (AES-256)"
    except ClientError:
        risk_score += 20
        issues.append("Missing Encryption")

    versioning = "❌ Disabled"
    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if ver.get('Status') == 'Enabled':
            versioning = "✅ Enabled"
        else:
            risk_score += 10
            issues.append("No Versioning")
    except ClientError:
        pass

    status = "DANGER" if risk_score >= 30 else "SAFE"
    
    return {
        "Name": bucket_name,
        "Status": status,
        "Risk Score": risk_score,
        "PublicAccessBlock": public_status,
        "Encryption": encryption,
        "Versioning": versioning
    }

# UI - main application
def main():
    with st.sidebar:
        st.header("🔑 AWS Configuration")
        st.info("Your keys are used locally and never stored.")
        aws_key = st.text_input("AWS Access Key ID", type="password")
        aws_secret = st.text_input("AWS Secret Access Key", type="password")
        region = st.selectbox("Region", ["us-east-1", "us-west-1", "ap-south-1", "eu-west-1"])
        
        start_btn = st.button("🚀 Start Cloud Scan", type="primary")

    st.title("☁️ CloudGuard Analyzer")
    st.markdown("**Automated S3 Misconfiguration & Security Auditor**")

    if start_btn and aws_key and aws_secret:
        try:
            session = boto3.Session(
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
                region_name=region
            )
            s3 = session.client('s3')
            
            with st.spinner("Connecting to AWS & Scanning Buckets..."):
                response = s3.list_buckets()
                buckets = response['Buckets']
                
                results = []
                progress_bar = st.progress(0)
                
                for i, bucket in enumerate(buckets):
                    res = scan_bucket(s3, bucket['Name'])
                    results.append(res)
                    progress_bar.progress((i + 1) / len(buckets))
                
                total = len(results)
                danger = len([r for r in results if r['Status'] == 'DANGER'])
                
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Buckets", total)
                c2.metric("Insecure Buckets", danger, delta=-danger, delta_color="inverse")
                c3.metric("Secure Buckets", total - danger, delta=total-danger)
                
                st.divider()
                
                st.subheader("🔍 Detailed Audit Findings")
                
                for res in results:
                    with st.expander(f"{'🔴' if res['Status'] == 'DANGER' else '🟢'} {res['Name']} (Score: {res['Risk Score']})"):
                        c1, c2 = st.columns(2)
                        with c1:
                            st.write(f"**Public Access:** {res['PublicAccessBlock']}")
                            st.write(f"**Encryption:** {res['Encryption']}")
                        with c2:
                            st.write(f"**Versioning:** {res['Versioning']}")
                            if res['Status'] == "DANGER":
                                st.error("Remediation: Enable 'Block Public Access' in AWS Console immediately.")
                
                st.divider()
                st.subheader("📄 Compliance Report")
                if st.button("Generate PDF Report"):
                    report_file = generate_pdf(results)
                    with open(report_file, "rb") as f:
                        st.download_button("Download Audit PDF", f, file_name="CloudGuard_Audit.pdf")

        except ClientError as e:
            st.error(f"AWS Authentication Failed: {e}")
        except Exception as e:
            st.error(f"An error occurred: {e}")
            
    elif start_btn:
        st.warning("Please enter your AWS Credentials in the sidebar.")
    else:
        st.info("👈 Enter your AWS Keys in the sidebar to begin the security audit.")

if __name__ == "__main__":
    main()
