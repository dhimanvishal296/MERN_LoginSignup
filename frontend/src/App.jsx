import Login from "./components/Login/Login";
import Signup from "./components/Signup/Signup";
import Home from "./components/Home";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"; // Fixed BrowserRoute to BrowserRouter
import "./App.css";

const App = () => {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/signup"/>} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/login" element={<Login />} />
          <Route path="/home" element={<Home />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
};

export default App;
