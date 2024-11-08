import React, { useRef, useState } from "react";
import { motion } from "framer-motion";
import logo from "../assets/Images/logo.png";

function Home() {
  const fileInput1Ref = useRef(null);
  const fileInput2Ref = useRef(null);

  const [uploadProgress1, setUploadProgress1] = useState(0);
  const [uploadProgress2, setUploadProgress2] = useState(0);
  const [uploadSuccess1, setUploadSuccess1] = useState(false);
  const [uploadSuccess2, setUploadSuccess2] = useState(false);
  const [fileName1, setFileName1] = useState("");
  const [fileName2, setFileName2] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [comparisonResult, setComparisonResult] = useState("");

  const handleClickFileInput = (inputRef) => {
    inputRef.current?.click();
  };

  const handleFileChange = (
    event,
    setUploadProgress,
    setUploadSuccess,
    setFileName
  ) => {
    const file = event.target.files[0];
    if (file) {
      setFileName(file.name);
      setUploadSuccess(false);
      setUploadProgress(0);

      const interval = setInterval(() => {
        setUploadProgress((prevProgress) => {
          if (prevProgress >= 100) {
            clearInterval(interval);
            setUploadSuccess(true);
            return 100;
          }
          return prevProgress + 10;
        });
      }, 200);
    }
  };

  const handleRemoveFile = (
    setFileName,
    setUploadSuccess,
    setUploadProgress
  ) => {
    setFileName("");
    setUploadSuccess(false);
    setUploadProgress(0);
  };

  // Handle compare action
  const handleCompare = async () => {
    if (!fileName1 || !fileName2) {
      alert("Both files must be uploaded");
      return;
    }

    // Log that files are being sent
    console.log("Sending files to the backend...");

    const formData = new FormData();
    formData.append("file1", fileInput1Ref.current.files[0]);
    formData.append("file2", fileInput2Ref.current.files[0]);

    setIsProcessing(true); // Show processing status

    try {
      const response = await fetch("http://localhost:5000/compare", {
        method: "POST",
        body: formData,
        credentials: "include", // Include cookies with the request
      });

      if (response.ok) {
        const data = await response.json();
        console.log("Files sent to backend successfully:", data);
        alert("Files compared successfully!");
        setComparisonResult(data.download_url); // Set the download URL for the comparison result
      } else {
        let errorMsg = "Error comparing files.";
        try {
          const errorData = await response.json();
          errorMsg = errorData.error || errorMsg;
        } catch (err) {
          console.error("Failed to parse error response:", err);
        }
        console.error("Error comparing files:", errorMsg);
        alert(`Error comparing files: ${errorMsg}`);
      }
    } catch (error) {
      console.error("Error sending files to backend:", error);
      alert("Failed to compare files");
    } finally {
      setIsProcessing(false); // Hide processing status
    }
  };

  return (
    <>
      <img src={logo} className="absolute top-0 left-0 p-2 w-1/6" />
      <div className="h-screen flex flex-col items-center bg-gray-100 justify-center px-4">
        <h1 className="md:text-5xl text-2xl pb-12 pt-8 font-extrabold text-gray-800 font-rubik relative z-20 text-center">
          Welcome to{" "}
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-pink-500 to-violet-500 font-rubik">
            SketchVision AI
          </span>
        </h1>

        <div className="flex justify-between gap-12 mt-10 w-full max-w-4xl">
          {/* File Upload Area 1 */}
          <motion.div
            initial={{ x: "-10vw", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{
              duration: 1,
              type: "easeOut",
              stiffness: 30,
              damping: 20,
            }}
            className="w-full sm:w-1/2 h-60 border-2 border-dashed border-gray-300 flex flex-col items-center justify-center cursor-pointer bg-gray-50 hover:bg-gray-100 rounded-xl transition-all"
            onDrop={(e) => e.preventDefault()}
            onDragOver={(e) => e.preventDefault()}
          >
            <p className="text-gray-500 text-lg">Drag and Drop File 1</p>

            <button
              onClick={() => handleClickFileInput(fileInput1Ref)}
              className="mt-4 bg-blue-500 text-white px-6 py-3 rounded-md hover:bg-blue-600 transition-all"
            >
              Upload File 1
            </button>
            <input
              type="file"
              ref={fileInput1Ref}
              className="hidden"
              onChange={(e) =>
                handleFileChange(
                  e,
                  setUploadProgress1,
                  setUploadSuccess1,
                  setFileName1
                )
              }
            />

            {/* Progress Bar */}
            {uploadProgress1 > 0 && uploadProgress1 < 100 && (
              <div className="mt-4 w-3/4 bg-gray-200 rounded-full h-2.5">
                <div
                  style={{ width: `${uploadProgress1}%` }}
                  className="bg-blue-500 h-2.5 rounded-full transition-all"
                ></div>
              </div>
            )}

            {/* Success Message and File Name */}
            {uploadSuccess1 && (
              <>
                <p className="text-green-600 mt-2">
                  File 1 uploaded successfully!
                </p>
                <div className="flex items-center mt-1 space-x-2">
                  <span className="text-gray-700">{fileName1}</span>
                  <button
                    onClick={() =>
                      handleRemoveFile(
                        setFileName1,
                        setUploadSuccess1,
                        setUploadProgress1
                      )
                    }
                    className="text-red-500 hover:text-red-700"
                  >
                    ✕
                  </button>
                </div>
              </>
            )}
          </motion.div>

          {/* File Upload Area 2 */}
          <motion.div
            initial={{ x: "10vw", opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{
              duration: 1,
              type: "easeInOut",
              stiffness: 30,
              damping: 20,
            }}
            className="w-full sm:w-1/2 h-60 border-2 border-dashed border-gray-300 flex flex-col items-center justify-center cursor-pointer bg-gray-50 hover:bg-gray-100 rounded-xl transition-all"
            onDrop={(e) => e.preventDefault()}
            onDragOver={(e) => e.preventDefault()}
          >
            <p className="text-gray-500 text-lg">Drag and Drop File 2</p>

            <button
              onClick={() => handleClickFileInput(fileInput2Ref)}
              className="mt-4 bg-blue-500 text-white px-6 py-3 rounded-md hover:bg-blue-600 transition-all"
            >
              Upload File 2
            </button>
            <input
              type="file"
              ref={fileInput2Ref}
              className="hidden"
              onChange={(e) =>
                handleFileChange(
                  e,
                  setUploadProgress2,
                  setUploadSuccess2,
                  setFileName2
                )
              }
            />

            {/* Progress Bar */}
            {uploadProgress2 > 0 && uploadProgress2 < 100 && (
              <div className="mt-4 w-3/4 bg-gray-200 rounded-full h-2.5">
                <div
                  style={{ width: `${uploadProgress2}%` }}
                  className="bg-blue-500 h-2.5 rounded-full transition-all"
                ></div>
              </div>
            )}

            {/* Success Message and File Name */}
            {uploadSuccess2 && (
              <>
                <p className="text-green-600 mt-2">
                  File 2 uploaded successfully!
                </p>
                <div className="flex items-center mt-1 space-x-2">
                  <span className="text-gray-700">{fileName2}</span>
                  <button
                    onClick={() =>
                      handleRemoveFile(
                        setFileName2,
                        setUploadSuccess2,
                        setUploadProgress2
                      )
                    }
                    className="text-red-500 hover:text-red-700"
                  >
                    ✕
                  </button>
                </div>
              </>
            )}
          </motion.div>
        </div>

        {/* Compare Button */}
        <button
          onClick={handleCompare}
          disabled={isProcessing}
          className="mt-8 bg-purple-600 text-white px-4 py-2 rounded-xl hover:bg-purple-700 transition-all"
        >
          {isProcessing ? "Processing..." : "Compare"}
        </button>

        {/* Download Button */}
        {comparisonResult && (
          <a
            href={comparisonResult}
            className="mt-4 bg-green-600 text-white px-4 py-2 rounded-xl hover:bg-green-700 transition-all"
            download="comparison.pdf" // Ensure the downloaded file has a .pdf extension
          >
            Download Comparison
          </a>
        )}
      </div>
    </>
  );
}

export default Home;
