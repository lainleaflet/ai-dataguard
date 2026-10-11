import streamlit as st
from security_check import analyze_prompt

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

if "history" not in st.session_state: 
            st.session_state["history"] = []

if st.button("analyze prompt"):
    if prompt.strip(): # .strip() helps with removing beginning whitespace, tabs, newlines from beginning and end of text :)
        st.write("entered: " + prompt);
        st.write("analyzing...");
        result = analyze_prompt(prompt);
        st.session_state["result"] = result

        if "history" not in st.session_state: 
            st.session_state["history"] = []
        # i was looking at online forums and documentation; apparently you need to declare the array this way no matter what 
        # to ensure that the list continues to update for its session. confused why i can't declare this array
        # outside of this if-not statement (globally, i mean as well).
        

        st.session_state["history"].append(result)

    else:
        st.write("please enter a prompt.");

if "result" in st.session_state:
    result = st.session_state["result"]
    st.divider()
    st.header("prompt analysis results")
    col1, col2, col3 = st.columns(3)

    with col1:
                st.write("**classification**")
    with col2:
                st.write("**recommended action**")
    with col3: 
                st.write("**prompt**")

    for prompt in st.session_state["history"]:
        with col1:
            st.write(prompt["classification"])

        with col2:
            st.write(prompt["action"])

        with col3:
            st.write(prompt["prompt"])
