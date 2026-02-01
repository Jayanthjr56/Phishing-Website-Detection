# Phishing Website Detection System

A complete machine learning-based phishing URL detection system that identifies malicious websites in real-time.

## 📊 Data Sources

- **Legitimate URLs**: [Tranco Top Sites List](https://tranco-list.eu/) - Top 1M most popular websites
- **Phishing URLs**: [Mitchell Krogza's Phishing Database](https://github.com/mitchellkrogza/Phishing.Database)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the Model

```bash
# Train with default settings (10,000 samples for quick testing)
python main.py --train

# Train with more samples for better accuracy
python main.py --train --samples 50000
```

### 3. Start the API Server

```bash
python main.py --api
```

Then open http://localhost:5000 in your browser.

### 4. Full Pipeline (Recommended)

```bash
python main.py --full
```

## 📁 Project Structure

```
phishing_detector/
├── main.py              
├── config.py            
├── data_collector.py    
├── feature_extractor.py 
├── model_trainer.py     
├── detector.py          
├── api.py              
├── requirements.txt     
├── templates/
│   └── index.html       
├── data/                
├── models/              
```
