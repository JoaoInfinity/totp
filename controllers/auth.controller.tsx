import crypto from "crypto";
import { Request, Response } from "express";
import * as OTPAuth from "otpauth";
import { encode } from "hi-base32";

import {
  collection,
  deleteDoc,
  getDocs,
  getFirestore,
  doc,
  addDoc,
  updateDoc,
  getDoc,
  setDoc,
} from "firebase/firestore";
import { firebaseConfig, auth, db } from "../firebase/firebase";
import { initializeApp } from "firebase/app";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
} from "firebase/auth";


interface IUser {
  id: string;
  name: string;
  email: string;
  otp_enabled: string;
}


interface IUserResponseSuccess {
  status: "success";
  user: IUser;
  message?: string;
}

interface IUserResponseError {
  status: "error";
  message: string;
  errorCode?: number; // Adicione propriedades adicionais se necessário
}

type IUserResponse = IUserResponseSuccess | IUserResponseError;


export const registerUser = async (
  name: any,
  email: any,
  password: any,
) => {
  try {
    // Crie o usuário no Firebase Authentication
    const userCredential = await createUserWithEmailAndPassword(
      auth,
      email,
      password
    );
    const user = userCredential.user;
    console.log(user);

    // Adicione o usuário ao Firestore usando o UID do usuário
    const userDocRef = doc(db, "users", user.uid);
    await setDoc(userDocRef, {
      name,
      email,
      otp_enabled: false,
      otp_verified: false,
      otp_auth_url: "",
      otp_base32: "",
    });

    return {
      status: "success",
      message: "Registered successfully, please login",
    };
  } catch (error: any) {
    // Verificar o código de erro corretamente
    if (error.code === "auth/email-already-in-use") {
      return {
        status: "fail",
        message: "Email already exists, please use another email address",
      };
    }
    return {
      status: "error",
      message: error.message || "An unknown error occurred",
    };
  }
};

export const loginUser = async (email: string, password: string): Promise<IUserResponse> => {
  try {
    // Autenticar o usuário no Firebase Authentication
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;

    console.log("Authenticated user UID:", user.uid);

    // Verifique se o usuário está autenticado
    if (!user) {
        throw new Error("No user with that email exists");
    }

    // Obtenha os dados do usuário do Firestore
    const userDocRef = doc(db, "users", user.uid);
    const userDoc = await getDoc(userDocRef);

    // Verifique se o documento existe
    if (!userDoc.exists()) {
      throw new Error("No user data found in Firestore");
    }

    // Obtenha os dados do usuário
    const userData = userDoc.data();
    const userResponse: IUser = {
      id: user.uid,
      name: userData?.name ?? '',  // Use an empty string if userData?.name is null or undefined
      email: user.email ?? '',  // No need for ! as user.email is already a string
      otp_enabled: userData?.otp_enabled ?? false,  // Use false if userData?.otp_enabled is null or undefined
    };

    return {
      status: "success",
      user: userResponse,
    };
  } catch (error) {
    console.error("Error during user login:", error);

    // Verificar o tipo de erro e retornar uma mensagem apropriada
    let errorMessage = "An unexpected error occurred";

    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === "string") {
      errorMessage = error;
    }

    return {
      status: "error",
      message: errorMessage,
      // Remover `errorCode` se não for necessário ou definir um valor apropriado
    } as IUserResponseError;
  }
};

export const generateRandomBase32 = () => {
  const buffer = crypto.randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return base32;
};

export const generateOTP = async (user_id: any) => {
  try {

    // Obtenha o documento do usuário do Firestore
    const userDocRef = doc(db, "users", user_id);
    const userDoc = await getDoc(userDocRef);


    if (!userDoc.exists()) {
      throw new Error("No user with that ID exists");
    }

    const base32_secret = generateRandomBase32();

    const totp = new OTPAuth.TOTP({
      issuer: "codevoweb.com",
      label: "CodevoWeb",
      algorithm: "SHA1",
      digits: 6,
      secret: base32_secret,
    });

    const otpauth_url = totp.toString();

    // Atualize o documento do usuário no Firestore
    await updateDoc(userDocRef, {
      otp_auth_url: otpauth_url,
      otp_base32: base32_secret,
    });

    return {
      status: "success",
      base32: base32_secret,
      otpauth_url,
    };
  } catch (error) {
    console.error("Error during generate OTP:", error);

    // Verificar o tipo de erro e retornar uma mensagem apropriada
    let errorMessage = "An unexpected error occurred";

    if (error instanceof Error) {
      errorMessage = error.message;
    } else if (typeof error === "string") {
      errorMessage = error;
    }

    return {
      status: "error",
      message: errorMessage,
    }
  }
};


export const verifyOTP = async (req: Request, res: Response) => {
  try {
    const { user_id, token } = req.body;

    const message = "Token is invalid or user doesn't exist";

    // Inicialize o Firebase App
    const app = initializeApp(firebaseConfig);

    // Inicialize Firestore
    const db = getFirestore(app);

    // Obtenha o documento do usuário do Firestore
    const userDocRef = doc(db, "users", user_id);
    const userDoc = await getDoc(userDocRef);

    if (!userDoc.exists()) {
      return res.status(401).json({
        status: "fail",
        message,
      });
    }

    const user = userDoc.data();

    let totp = new OTPAuth.TOTP({
      issuer: "codevoweb.com",
      label: "CodevoWeb",
      algorithm: "SHA1",
      digits: 6,
      secret: user.otp_base32,
    });

    let delta = totp.validate({ token });

    if (delta === null) {
      return res.status(401).json({
        status: "fail",
        message,
      });
    }

    // Atualize o documento do usuário no Firestore
    await updateDoc(userDocRef, {
      otp_enabled: true,
      otp_verified: true,
    });

    res.status(200).json({
      otp_verified: true,
      user: {
        id: user_id,
        name: user.name,
        email: user.email,
        otp_enabled: true,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error,
    });
  }
};

export const validateOTP = async (req: Request, res: Response) => {
  try {
    const { user_id, token } = req.body;

    // Obtenha o documento do usuário do Firestore
    const userDocRef = doc(db, "users", user_id);
    const userDoc = await getDoc(userDocRef);

    if (!userDoc.exists()) {
      return res.status(401).json({
        status: "fail",
        message: "Token is invalid or user doesn't exist",
      });
    }

    const user = userDoc.data();

    // Configure o TOTP com o segredo armazenado
    let totp = new OTPAuth.TOTP({
      issuer: "codevoweb.com",
      label: "CodevoWeb",
      algorithm: "SHA1",
      digits: 6,
      secret: user.otp_base32!,
    });

    // Valide o token
    let delta = totp.validate({ token, window: 1 });

    if (delta === null) {
      return res.status(401).json({
        status: "fail",
        message: "Token is invalid or user doesn't exist",
      });
    }

    res.status(200).json({
      otp_valid: true,
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error,
    });
  }
};

export const disableOTP = async (req: Request, res: Response) => {
  try {
    const { user_id } = req.body;

    // Obtenha o documento do usuário do Firestore
    const userDocRef = doc(db, "users", user_id);
    const userDoc = await getDoc(userDocRef);

    if (!userDoc.exists()) {
      return res.status(404).json({
        status: "fail",
        message: "User does not exist",
      });
    }

    // Atualize o documento do usuário no Firestore
    await updateDoc(userDocRef, {
      otp_enabled: false,
    });

    // Obtenha o usuário atualizado
    const updatedUserDoc = await getDoc(userDocRef);
    const updatedUser = updatedUserDoc.data();

    res.status(200).json({
      otp_disabled: true,
      user: {
        id: user_id,
        name: updatedUser?.name,
        email: updatedUser?.email,
        otp_enabled: updatedUser?.otp_enabled,
      },
    });
  } catch (error) {
    res.status(500).json({
      status: "error",
      message: error,
    });
  }
};

export default {
  registerUser,
  loginUser,
  generateOTP,
  verifyOTP,
  validateOTP,
  disableOTP,
};
