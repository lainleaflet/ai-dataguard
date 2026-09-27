import streamlit as st

st.set_page_config(
    page_title="ai dataguard",
    page_icon="🛡️",
    layout="wide"
)

st.title("ai dataguard");
st.subheader("tool to detect sensitive data in ai model inputs");

st.write("---");

prompt = st.text_area("enter your prompt here.", 
                      placeholder="type a sample request here...")

if st.button("analyze prompt"):
    if prompt.strip():
        st.write("entered: " + prompt);
        st.write("analyzing...");
    else:
        st.write("please enter a prompt.");
