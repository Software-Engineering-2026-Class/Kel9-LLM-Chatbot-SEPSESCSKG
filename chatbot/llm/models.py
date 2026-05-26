from dotenv import load_dotenv
import os

from langchain_openai import ChatOpenAI

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

# GPT
gpt_model = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0,
    api_key=OPENAI_API_KEY
)

# DeepSeek
deepseek_model = ChatDeepsek(
    model="deepseek-chat",
    temperature=0,
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com"
)