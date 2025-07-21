# SmartRule – Rule-Based Evaluation Engine

## 🧠 Project Overview  
**SmartRule** is a Python-based GUI application that enables users to define and evaluate conditional rules like:  
`if marks > 85 then grade = 'A'`

It applies key concepts from **Theory of Programming Languages (TPL)** such as:
- Context-Free Grammar (CFG)
- Parse Trees
- Static and Dynamic Semantics
- Subrange and Enumeration
- Rule-based logic & abstraction

Ideal for use cases like grading systems, bonus evaluations, and logic automation.

---

## 🚀 Key Features  
- GUI to add, edit, delete rules dynamically  
- Upload rule sets from `rules.txt`  
- Evaluate rules in real-time  
- Parse and validate user-defined logic  
- Visualize parse tree using **Graphviz**

---

## ⚙️ Technologies Used  
- **Language:** Python 3.x  
- **Libraries/Tools:**  
  - `tkinter` – GUI  
  - `re` – Parsing logic  
  - `graphviz` – Parse tree rendering

---

## 📚 Programming Language Concepts  
- **CFG (Context-Free Grammar):** Defines rule format (`if <condition> then <action>`)  
- **Parse Trees:** Visual representation of rule structure  
- **Static Semantics:** Validates rules before evaluation  
- **Dynamic Semantics:** Evaluates rules at runtime using user inputs  
- **Subrange:** Conditions like `marks >= 50 and marks <= 60`  
- **Enumeration:** Conditions like `grade in {'A', 'B', 'C'}`  
- **Data Abstraction:** Rules stored as structured objects in memory

---

## 📁 Project Structure  
SmartRule/
main.py                # Main GUI application with rule logic
rules.txt              # Sample rule definitions for evaluation
README.md              # Project overview and documentation
smartrule_workflow.png # Workflow diagram (logic flow)

---

## 📄 Sample Rule File: `rules.txt`
```txt
if marks >= 85 then grade = 'A'
if sales > 100000 then bonus = 0.1 * sales
if category in {'electronics', 'grocery'} then tax = 0.15 * price
