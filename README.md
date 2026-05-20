# SEPSES Cybersecurity Knowledge Graph Chatbot

SEPSES Cybersecurity Knowledge Graph Chatbot is an LLM-based cybersecurity analysis assistant that integrates Large Language Models (LLMs) with the SEPSES Cybersecurity Knowledge Graph (CSKG) to provide explainable and context-aware cybersecurity analysis.

Unlike general-purpose AI chatbots that rely only on pretrained language knowledge, this system utilizes structured cybersecurity knowledge from SEPSES CSKG combined with Retrieval-Augmented Generation (RAG) / GraphRAG mechanisms to reduce hallucination and improve analytical accuracy.

The chatbot supports cybersecurity question-answering, threat actor analysis, malware investigation, vulnerability relationship analysis, and security log analysis.

## Team Members
- Diayu Nur Aini          24/537751/PA/22792 - Diayu Nur Aini
- Freta Yordinia Laura    24/533444/PA/22576 - Yor
- Herlina Iin Nur Soleha  24/541333/PA/22962 - Herlina-Iin
- Ananda Auliya Rahma     24/533691/PA/22608 - anandauliya

## Project Objectives
- Integrate SEPSES CSKG with LLMs for cybersecurity analysis
- Implement GraphRAG / RAG architecture
- Support explainable cybersecurity question-answering
- Analyze relationships between vulnerabilities, malware, threat actors, and attacks
- Evaluate multiple LLMs for cybersecurity tasks
- Provide an interactive chatbot interface for analysts and researchers

## Features

### Cybersecurity Question Answering
- Ask cybersecurity-related questions using natural language
- Retrieve structured information from SEPSES CSKG
- Generate explainable responses with graph context

### Threat Actor Analysis
- Analyze threat actors and associated attack patterns
- Discover related malware, vulnerabilities, and campaigns

### Malware Investigation
- Investigate malware families and their behaviors
- Explore malware relationships within the knowledge graph

### Vulnerability Relationship Analysis
- Analyze CVE relationships
- Discover affected systems, attack vectors, and linked malware

### Security Log Analysis
- Upload and analyze local security logs
- Combine vector database retrieval with LLM reasoning

### RAG / GraphRAG Integration
- Knowledge retrieval from RDF/SPARQL resources
- Context-aware answer generation using LLMs

## Vocabularies
Several vocabularies are developed to represent the SEPSES-CSKG knowledge graphs, as follows:

| Prefix | Description                               | Link                                                                                   |
|--------|-------------------------------------------|----------------------------------------------------------------------------------------|
| capec  | Common Attack Pattern Enumeration and Classification (CAPEC) | <a href="http://w3id.org/sepses/vocab/ref/capec" target="_blank">http://w3id.org/sepses/vocab/ref/capec</a>     |
| cwe    | Common Weakness Enumeration (CWE)         | <a href="http://w3id.org/sepses/vocab/ref/cwe" target="_blank">http://w3id.org/sepses/vocab/ref/cwe</a>         |
| cve    | Common Vulnerabilities and Exposures (CVE) | <a href="http://w3id.org/sepses/vocab/ref/cve" target="_blank">http://w3id.org/sepses/vocab/ref/cve</a>         |
| cvss   | Common Vulnerability Scoring System (CVSS)| <a href="http://w3id.org/sepses/vocab/ref/cvss" target="_blank">http://w3id.org/sepses/vocab/ref/cvss</a>       |
| cpe    | Common Platform Enumeration (CPE)         | <a href="http://w3id.org/sepses/vocab/ref/cpe" target="_blank">http://w3id.org/sepses/vocab/ref/cpe</a>         |


## Installation

### Requirements

To run this prototype, the prerequisite is that you have a JDK 8+ and Maven installed in your computer.

### Configuration
Additionally, the config.properties is build for local Jena fuseki installation. Make sure that: 
* the `config.properties` is available (and adjust it if necessary; especially with regards to the triplestore/fuseki installation)
* you have an empty repo called 'sepses' in your fuseki/virtuoso installation
    * you can also run it without storing the data to triplestore using "dummy" as storage
    * currently still need an active sparql endpoint (TODO: to fix this).


### Run the Code

The following steps are required to run the engine: 
* run `mvn clean` to build the required jar files from the `lib` folder
* run `mvn install -DskipTests=true` to build the application
    * optionally, you can also run the tests (without the `-DskipTests=true`) to run checks of extracted data against a set of SHACL constraints to make sure that the conversion for each source is correctly defined
* run `java -jar target/cyber-kb-<version>-jar-with-dependencies.jar -p <type-of-source>` 
    * replace `<type-of-source>` with one of the following: capec, cwe, cve, cat, icsa )
    * replace `<version>` with the version of the Cyber-KB
    * (optional) you can also add `-v` as parameter to activate SHACL constraint checking 
        * Note: this option may add a significant time to the process (especially for CPE)

The prototype will then 
* (i) generate the RDF graph from these sources and create necessary linking
* (ii) (*optional*) check the generated RDF data against a set of SHACL constraints (using constraints from `src/main/resources/shacl/*.ttl`)
* (iii) store the data in the triplestore

We have tried and tested it in OSX (Intel i7@3,1GHz, OSX Mojave, 16GB RAM). 
The benchmark result (excluding SHACL check) is available in the following [link](https://github.com/sepses/cyber-kg-converter/blob/master/doc/benchmark.png)

## Access Services

Example queries are now added (`example-queries.txt`), which can be tested in our [SPARQL endpoint](https://w3id.org/sepses/sparql).

Other interface beyond SPARQL are also provided, such as [Linked Data Interface](https://sepses.ifs.tuwien.ac.at/resource/cve/CVE-2018-4449) (example),  [Triple Pattern Fragment](http://ldf-server.sepses.ifs.tuwien.ac.at/) and [Dump-files](https://sepses.ifs.tuwien.ac.at/index.php/datasets/)   (in .turtle and .HDT).

## License

The ECS-SEC KG Engine is written by SEPSES team and released under the [MIT license](http://opensource.org/licenses/MIT).
