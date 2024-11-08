import React, { useState } from "react";
import { useNavigate } from "react-router-dom"; // Import useNavigate from react-router-dom
import { Boxes } from "./background-boxes"; // Assuming you have the background boxes component
import Button from "./button"; // Assuming you have the Button component
import Lottie from "lottie-react"; // Assuming you have Lottie for animations
import Animation from "../assets/Animations/Animation - 1730955775370.json"; // Your Lottie animation
import logo from "../assets/Images/logo.png"; // Your logo image

export function BackgroundBoxesDemo() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const navigate = useNavigate(); // Initialize useNavigate hook

  const openModal = () => setIsModalOpen(true);
  const closeModal = () => {
    setIsModalOpen(false);
    setErrorMessage(""); // Clear any previous error messages
  };

  // Handle login button click
  const handleLogin = async (e) => {
    e.preventDefault();
    const email = document.querySelector('input[type="text"]').value;
    const password = document.querySelector('input[type="password"]').value;

    try {
      // In backgroundBoxesDemo.jsx
      const response = await fetch("http://localhost:5000/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include", // Include cookies with the request
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      console.log("Response Data:", data); // Log the response data

      // Redirect to home page if login is successful
      if (response.ok) {
        navigate("/home");
      } else {
        setErrorMessage(data.message || "Login failed");
      }
    } catch (error) {
      console.error("Login error:", error);
      setErrorMessage("An error occurred during login.");
    }
  };

  return (
    <div className="h-screen relative w-full overflow-hidden bg-white flex flex-col items-center justify-center">
      <img src={logo} className="z-20 absolute top-0 left-0 p-2 w-1/6" />
      <div className="absolute inset-0 w-full h-full bg-white z-10 [mask-image:radial-gradient(transparent,white)] pointer-events-none" />
      <Boxes />
      <h1 className="md:text-6xl text-xl font-extrabold text-gray-800 font-rubik relative z-20">
        Welcome to{" "}
        <span className="bg-clip-text text-transparent bg-gradient-to-r from-pink-500 to-violet-500 font-rubik">
          SketchVision AI
        </span>
      </h1>
      <div className="relative z-30 pt-6 pb-12">
        <Button onClick={openModal}>Login</Button>
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 z-40 bg-black bg-opacity-60 flex items-center justify-center">
          <div className="bg-white w-7/12 h-3/5 rounded-lg shadow-lg flex relative">
            {/* Left half with Lottie animation */}
            <div className="w-1/2 rounded-l-lg flex items-center justify-center overflow-hidden">
              <Lottie
                animationData={Animation}
                style={{ width: "100%", height: "100%" }}
              />
            </div>

            {/* Right half with login form */}
            <div className="w-1/2 p-6">
              <h2 className="text-2xl font-bold mb-4">Login</h2>
              <form>
                <label className="block mb-2">
                  <span className="text-gray-700">Username</span>
                  <input
                    type="text"
                    className="mt-1 block w-full p-2 border border-gray-300 rounded"
                  />
                </label>
                <label className="block mb-8">
                  <span className="text-gray-700">Password</span>
                  <input
                    type="password"
                    className="mt-1 block w-full p-2 border border-gray-300 rounded"
                  />
                </label>
                {errorMessage && (
                  <div className="text-red-500 mb-4">{errorMessage}</div>
                )}
                <button
                  type="button"
                  onClick={handleLogin} // Call handleLogin to navigate
                  className="w-full bg-red-500 text-white py-2 rounded hover:bg-red-600"
                >
                  Login
                </button>
              </form>
            </div>

            {/* Close "X" button in the top-right corner */}
            <button
              onClick={closeModal}
              className="absolute top-2 right-4 text-gray-500 hover:text-gray-800 text-xl font-bold"
            >
              &times;
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
