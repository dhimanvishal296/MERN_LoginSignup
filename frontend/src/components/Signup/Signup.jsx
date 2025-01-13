import "./Signup.css";
import { useState } from "react";
import { Link} from "react-router-dom";
import axios from "axios"; // Import Axios

const PasswordErrorMessage = () => {
  return (
    <p className="FieldError">Password should have at least 8 characters</p>
  );
};

const validateEmail = (email) => {
  return String(email)
    .toLowerCase()
    .match(
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    );
};

const Signup = () => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState({
    value: "",
    isTouched: false,
  });

  const getIsFormValid = () => {
    // Implement this function
    return username && validateEmail(email) && password.value.length >= 8;
  };

  const clearForm = () => {
    // Implement this function
    setUsername("");
    setEmail("");
    setPassword({ value: "", isTouched: false });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
  
    try {
      // Send a POST request to the /signup API
      const response = await axios.post("http://localhost:5000/signup", {
        name: username,
        email: email,
        password: password.value,
      });
  
      // Handle success response
      alert(response.data.message || "Account created!");
      clearForm();
    } catch (error) {
      // Handle error response
      if (error.response) {
        alert(error.response.data.error || "Something went wrong!");
      } else {
        alert("Unable to connect to the server. Please try again later.");
      }
    }
  };
  

  return (
    <div className="container">
      <form onSubmit={handleSubmit}>
        <fieldset>
          <h2>Sign Up</h2>
          <div className="Field">
            <label>
              User Name <sup>*</sup>
            </label>
            <input
              placeholder="User Name"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>
          <div className="Field">
            <label>
              Email address <sup>*</sup>
            </label>
            <input
              placeholder="Email address"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="Field">
            <label htmlFor="password">
              Password <sup>*</sup>
            </label>
            <input
              type="password"
              value={password.value}
              onChange={(e) => {
                setPassword({ ...password, value: e.target.value });
              }}
              onBlur={() => {
                setPassword({ ...password, isTouched: true });
              }}
              placeholder="Password"
            />
            {password.isTouched && password.value.length < 8 ? (
              <PasswordErrorMessage />
            ) : null}
          </div>

          <button type="submit" disabled={!getIsFormValid()}>
            Create account
          </button>
          <p className="helperText">
            Already have an account! <Link to="/login">Login</Link>
          </p>
        </fieldset>
      </form>
    </div>
  );
};

export default Signup;
