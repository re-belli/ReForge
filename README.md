# ReForge
## AI-assisted semantic source reconstruction from binaries for vulnerability discovery.

AI logic is encorporated but needs tuning for the final output file can be built with gcc -fsyntax-only.

Working on CodeQl integration piece. 


## Instructions to use Project
### Download Ghidra into the ReForge folder and run it so that the script structure is setup.

### Install ollama
curl -fsSL https://ollama.com/install.sh | sh

### Enable and start service
sudo systemctl enable ollama
sudo systemctl start ollama

### Check status
sudo systemctl status ollama

### Pull DeepSekk-Coder 6.7B (Choose model you want)
ollama pull deepseek-coder:6.7b
