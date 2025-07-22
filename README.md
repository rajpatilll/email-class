# 🛡️ Phishing Detection System

A lightweight phishing detection platform that combines a machine learning backend with a user-friendly frontend interface. Built using Python and JavaScript, the system provides real-time analysis of web content and predicts phishing threats with high accuracy.

##  Features

-  **Naïve Bayes Classifier**: Trained on labeled phishing datasets to detect suspicious URLs and forms with up to **97% accuracy**.
-  **Interactive Front-End**: Built with HTML, CSS, and JavaScript to provide a responsive user interface for live detection and feedback.
-  **Real-World Applicability**: Designed for seamless integration into web workflows and educational tools to raise phishing awareness.

##  Tech Stack

- **Backend**: Python, Scikit-learn
- **Frontend**: HTML, CSS, JavaScript
- **Model**: Naïve Bayes Classifier
- **Deployment-ready**: Easily integratable into existing web applications

##  How It Works

1. User inputs a suspicious URL or HTML snippet.
2. Backend extracts key features (e.g., use of IPs, suspicious keywords, length of URL).
3. Trained Naïve Bayes model predicts the likelihood of phishing.
4. Result and risk level are displayed via the front-end interface.


##  Accuracy

- Achieved **97% accuracy** on real-world test samples
- Trained and validated on publicly available phishing datasets (e.g., PhishTank)

##  Future Improvements

- Add support for deep learning models (LSTM or transformers)
- Deploy as a browser extension or Chrome plugin
- Integrate with WHOIS and DNS APIs for advanced verification

## 📜 License

This project is licensed under the MIT License. See `LICENSE` for details.

## 🤝 Contributions

Feel free to fork this repository and submit pull requests. Suggestions and improvements are welcome!



