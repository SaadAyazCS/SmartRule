import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel, filedialog
from graphviz import Digraph

# =============================
# Data Abstraction
# =============================
class Rule:
    def __init__(self, condition, action):
        self.condition = condition.strip()
        self.action = action.strip()

    # =============================
    # Dynamic Programming
    # =============================
    def evaluate(self, data):
        try:
            if eval(self.condition, {}, data):
                exec(self.action, {}, data)
                return True
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

# =============================
# CFG + Parse Tree
# =============================
class SmartRuleEngine:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule_str):
        import re
        match = re.match(r"if (.+) then (.+)", rule_str.strip())
        if match:
            condition, action = match.groups()
            rule = Rule(condition, action)
            self.rules.append(rule)
            return True
        return False

    def get_rules(self):
        return self.rules

    def evaluate_rules(self, data):
        applied_rules = []
        for rule in self.rules:
            if rule.evaluate(data):
                applied_rules.append(f"IF {rule.condition} THEN {rule.action}")
        return applied_rules, data

# =============================
# GUI with Styling + Features
# =============================
class SmartRuleApp:
    def __init__(self, root):
        self.engine = SmartRuleEngine()

        root.title("SmartRule: Rule-Based Evaluator")
        root.geometry("720x650")
        root.configure(bg="#f0f4f8")

        menu = tk.Menu(root)
        root.config(menu=menu)
        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Rules", command=self.save_rules)
        file_menu.add_command(label="Load Rules", command=self.load_rules)

        heading = tk.Label(root, text="SmartRule Engine", font=("Helvetica", 20, "bold"), bg="#f0f4f8", fg="#003366")
        heading.pack(pady=10)

        tk.Label(root, text="Enter Rule (if ... then ...):", bg="#f0f4f8", font=("Arial", 12)).pack()
        self.rule_entry = tk.Entry(root, width=80, font=("Arial", 11))
        self.rule_entry.pack(pady=5)

        button_frame = tk.Frame(root, bg="#f0f4f8")
        button_frame.pack(pady=5)
        tk.Button(button_frame, text="Add Rule", command=self.add_rule, width=15, bg="#007acc", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(button_frame, text="Show Rules", command=self.show_rules, width=15, bg="#6a1b9a", fg="white").grid(row=0, column=1)
        tk.Button(button_frame, text="Upload Rules File", command=self.upload_rules_file, width=20, bg="#ffa000", fg="black").grid(row=0, column=2, padx=10)

        tk.Label(root, text="Enter Input Data (e.g., marks=85):", bg="#f0f4f8", font=("Arial", 12)).pack(pady=(20, 0))
        self.input_text = scrolledtext.ScrolledText(root, width=60, height=5, font=("Consolas", 11))
        self.input_text.pack(pady=5)

        tk.Button(root, text="Run Evaluation", command=self.run_engine, width=20, bg="green", fg="white", font=("Arial", 11, "bold")).pack(pady=10)

        tk.Label(root, text="Rules Applied:", bg="#f0f4f8", font=("Arial", 12)).pack()
        self.rules_output = scrolledtext.ScrolledText(root, width=80, height=7, font=("Consolas", 11), bg="#e8f5e9")
        self.rules_output.pack(pady=5)

        tk.Label(root, text="Final Data Output:", bg="#f0f4f8", font=("Arial", 12)).pack()
        self.final_data_output = tk.Text(root, height=5, width=80, font=("Consolas", 11), bg="#fff3e0")
        self.final_data_output.pack(pady=5)

    def add_rule(self):
        rule = self.rule_entry.get()
        if self.engine.add_rule(rule):
            messagebox.showinfo("Rule Added", f"Added Rule:\n{rule}")
            self.rule_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Invalid Rule", "Use format: if <condition> then <action>")

    def show_rules(self):
        rules_window = Toplevel()
        rules_window.title("Saved Rules")
        rules_window.geometry("550x500")
        rules_window.configure(bg="#f5f5f5")

        tk.Label(rules_window, text="All Defined Rules", font=("Arial", 14, "bold"), bg="#f5f5f5").pack(pady=10)

        self.rule_listbox = tk.Listbox(rules_window, width=70, height=10, font=("Consolas", 11))
        self.rule_listbox.pack(padx=10, pady=5)

        self.rules_in_popup = self.engine.get_rules()
        for idx, r in enumerate(self.rules_in_popup):
            self.rule_listbox.insert(tk.END, f"{idx+1}. IF {r.condition} THEN {r.action}")

        tk.Label(rules_window, text="Edit Selected Rule:", bg="#f5f5f5", font=("Arial", 12)).pack(pady=(10, 0))
        self.edit_entry = tk.Entry(rules_window, width=70, font=("Arial", 11))
        self.edit_entry.pack(pady=5)

        edit_frame = tk.Frame(rules_window, bg="#f5f5f5")
        edit_frame.pack(pady=5)

        tk.Button(edit_frame, text="Load for Editing", command=self.load_selected_rule, width=15, bg="#007acc", fg="white").grid(row=0, column=0, padx=10)
        tk.Button(edit_frame, text="Update Rule", command=self.update_rule, width=15, bg="#4caf50", fg="white").grid(row=0, column=1)
        tk.Button(edit_frame, text="Delete Rule", command=self.delete_rule, width=15, bg="#e53935", fg="white").grid(row=0, column=2, padx=10)

        tk.Button(rules_window, text="Show Parse Tree", command=self.show_parse_tree, bg="#ff9800", fg="white").pack(pady=10)

    def load_selected_rule(self):
        selected = self.rule_listbox.curselection()
        if not selected:
            messagebox.showwarning("No selection", "Please select a rule to edit.")
            return
        idx = selected[0]
        rule = self.rules_in_popup[idx]
        self.edit_entry.delete(0, tk.END)
        self.edit_entry.insert(0, f"if {rule.condition} then {rule.action}")
        self.current_edit_index = idx

    def update_rule(self):
        if not hasattr(self, 'current_edit_index'):
            messagebox.showwarning("No rule loaded", "Please load a rule first.")
            return
        updated_rule = self.edit_entry.get().strip()
        import re
        match = re.match(r"if (.+) then (.+)", updated_rule)
        if not match:
            messagebox.showerror("Invalid Format", "Use format: if <condition> then <action>")
            return
        condition, action = match.groups()
        new_rule = Rule(condition, action)
        self.engine.rules[self.current_edit_index] = new_rule
        self.rule_listbox.delete(0, tk.END)
        for idx, r in enumerate(self.engine.rules):
            self.rule_listbox.insert(tk.END, f"{idx+1}. IF {r.condition} THEN {r.action}")
        messagebox.showinfo("Rule Updated", "Rule updated successfully.")

    def delete_rule(self):
        if not hasattr(self, 'current_edit_index'):
            messagebox.showwarning("No rule selected", "Please load a rule to delete.")
            return
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this rule?")
        if confirm:
            del self.engine.rules[self.current_edit_index]
            self.rule_listbox.delete(0, tk.END)
            for idx, r in enumerate(self.engine.rules):
                self.rule_listbox.insert(tk.END, f"{idx+1}. IF {r.condition} THEN {r.action}")
            self.edit_entry.delete(0, tk.END)
            messagebox.showinfo("Deleted", "Rule deleted successfully.")

    def show_parse_tree(self):
        selected = self.rule_listbox.curselection()
        if not selected:
            messagebox.showwarning("No rule", "Please select a rule.")
            return
        idx = selected[0]
        rule = self.rules_in_popup[idx]
        dot = Digraph()
        dot.node('IF', 'if')
        dot.node('COND', rule.condition)
        dot.node('THEN', 'then')
        dot.node('ACT', rule.action)
        dot.edges([('IF', 'COND'), ('IF', 'THEN'), ('THEN', 'ACT')])
        dot.render('parse_tree', view=True, format='png')

    def save_rules(self):
        try:
            with open("rules.txt", "w") as f:
                for rule in self.engine.rules:
                    f.write(f"if {rule.condition} then {rule.action}\n")
            messagebox.showinfo("Saved", "Rules saved to rules.txt")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_rules(self):
        try:
            with open("rules.txt", "r") as f:
                self.engine.rules.clear()
                for line in f:
                    self.engine.add_rule(line.strip())
            messagebox.showinfo("Loaded", "Rules loaded from rules.txt")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def upload_rules_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "r") as f:
                    self.engine.rules.clear()
                    for line in f:
                        self.engine.add_rule(line.strip())
                messagebox.showinfo("Uploaded", f"Rules loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def run_engine(self):
        input_lines = self.input_text.get("1.0", tk.END).strip().splitlines()
        data = {}
        try:
            for line in input_lines:
                if '=' in line:
                    key, value = line.split('=')
                    data[key.strip()] = eval(value.strip())
        except:
            messagebox.showerror("Input Error", "Invalid input format. Use key=value")
            return
        applied, final_data = self.engine.evaluate_rules(data)
        self.rules_output.delete("1.0", tk.END)
        if applied:
            for r in applied:
                self.rules_output.insert(tk.END, f"{r}\n")
        else:
            self.rules_output.insert(tk.END, "No rules applied.\n")
        self.final_data_output.delete("1.0", tk.END)
        self.final_data_output.insert(tk.END, str(final_data))

# =============================
# Main Loop
# =============================
if __name__ == "__main__":
    root = tk.Tk()
    app = SmartRuleApp(root)
    root.mainloop()