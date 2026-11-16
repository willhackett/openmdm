import { render } from "preact";
import { initApi } from "./api";
import { App } from "./App";
import "./styles.css";

initApi().then(() => {
  render(<App />, document.getElementById("app")!);
});
