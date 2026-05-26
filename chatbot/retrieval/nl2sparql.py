from langchain.prompts import PromptTemplate

from chatbot.retrieval.ontology_context import ONTOLOGY_CONTEXT
from chatbot.api.sparql_client import run_query, bindings_to_rows
from chatbot.llm.models import gpt_model


template = """
You are a cybersecurity SPARQL expert.

Translate the user question into valid SPARQL.

Use the ontology below.

Ontology:
{ontology}

Question:
{question}

Return ONLY SPARQL query.
"""


prompt = PromptTemplate(
    input_variables=["ontology", "question"],
    template=template
)


def generate_sparql(question: str):

    chain = prompt | gpt_model

    response = chain.invoke({
        "ontology": ONTOLOGY_CONTEXT,
        "question": question
    })

    return response.content.strip()


def execute_question(question: str):

    sparql_query = generate_sparql(question)

    raw_result = run_query(sparql_query)

    rows = bindings_to_rows(raw_result)

    return {
        "question": question,
        "sparql": sparql_query,
        "results": rows
    }


if __name__ == "__main__":

    q = "Show information about CVE-2021-44228"

    result = execute_question(q)

    print(result["sparql"])

    print()

    for r in result["results"]:
        print(r)