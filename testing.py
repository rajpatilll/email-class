import pandas as pd
import nltk
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score
import pickle
import swifter

# Download necessary NLTK data
nltk.download('punkt')

# Load the CSV file (adjust the path to your file)
csv_file_path = 'C:\\Users\\Acer\\Downloads\\Spam-Email-Classification-main\\Spam-Email-Classification-main\\spam.csv'

# Load relevant columns from the dataset
df = pd.read_csv(csv_file_path, usecols=['Email Text', 'Email Type'])

# Convert labels to numerical values: 'Safe Email' -> 0, 'Phishing Email' -> 1
df['Email Type'] = df['Email Type'].apply(lambda x: 1 if x == 'Phishing Email' else 0)

# Check if data loaded correctly
print(f"Total emails loaded: {len(df)}")
print(df.head())  # Display the first few rows to verify the content

# Preprocessing function to clean and tokenize the text
def preprocess_text(text):
    if isinstance(text, str):
        text = text.lower()  # Convert to lowercase
        text = nltk.word_tokenize(text)  # Tokenize the text
        text = [word for word in text if word.isalnum()]  # Remove non-alphanumeric characters
        return " ".join(text)
    return ""

# Apply preprocessing to the 'Email Text' column
df['Email Text'] = df['Email Text'].swifter.apply(preprocess_text)

# Check preprocessed data
print(df.head())

# Split the dataset into training and test sets (80% training, 20% testing)
X_train, X_test, y_train, y_test = train_test_split(df['Email Text'], df['Email Type'], test_size=0.2, random_state=42)

# Vectorize the text data using TF-IDF
vectorizer = TfidfVectorizer(max_df=0.9, min_df=5, ngram_range=(1, 2))
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Train the Naive Bayes model
model = MultinomialNB()
model.fit(X_train_tfidf, y_train)

# Make predictions on the test set
y_pred = model.predict(X_test_tfidf)

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model and vectorizer using pickle
pickle.dump(model, open('model_phishing.pkl', 'wb'))
pickle.dump(vectorizer, open('vectorizer_phishing.pkl', 'wb'))

print("Model and vectorizer saved successfully!")
