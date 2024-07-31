import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyCTPHB0CqN4nlcSVRnOwpiJt8ZmVKl4dxY",
  authDomain: "relogio-ponto-1c5e8.firebaseapp.com",
  projectId: "relogio-ponto-1c5e8",
  storageBucket: "relogio-ponto-1c5e8.appspot.com",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

export { app, auth, db, firebaseConfig };
