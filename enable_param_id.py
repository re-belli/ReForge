from ghidra.app.script import GhidraScript

class EnableEffectiveDecompiler(GhidraScript):
    def run(self):
        if currentProgram is None:
            print("No program is open! Aborting.")
            return

        print("[*] Enabling effective decompiler options...")

        analysis_options_to_set = {
            "Decompiler Parameter ID": "true",
            "Decompiler Parameter ID.Prototype Evaluation": "__thiscall",
            "Decompiler Parameter ID.Analysis Decompiler Timeout (sec)": "90",
            "Decompiler Switch Analysis": "true"
        }

        setAnalysisOptions(currentProgram, analysis_options_to_set)

        print("[*] Decompiler options enabled successfully!")

if __name__ == "__main__":
    script = EnableEffectiveDecompiler()
    script.run()
