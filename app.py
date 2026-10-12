import streamlit as st
from security_check import analyze_prompt

st.set_page_config(
    page_title="ai dataguard",
    page_icon="🛡️",
    layout="wide"
)

st.title("ai dataguard");
st.subheader("tool to detect sensitive data in ai model inputs");

st.divider()

if "history" not in st.session_state: 
        st.session_state["history"] = []
        # i was looking at online forums and documentation; apparently you need to declare the array this way no matter what 
        # to ensure that the list continues to update for its session. confused why i can't declare this array
        # outside of this if-not statement.

prompt = st.text_area("enter your prompt here.", 
                      placeholder="type a sample request here...")

if st.button("analyze prompt"):
    if prompt.strip(): # .strip() helps with removing beginning whitespace, tabs, newlines from beginning and end of text :)
        result = analyze_prompt(prompt);
        st.session_state["result"] = result
        st.session_state["history"].append(result)

    else:
        st.write("please enter a prompt.");

if st.session_state["history"]:
    st.divider()
    st.header("history of analyzed prompts")
    st.dataframe(st.session_state["history"], width="stretch")
