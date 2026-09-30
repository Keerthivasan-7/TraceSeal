import { Shell } from "./components/Shell";
import { AttackLab } from "./screens/AttackLab";
import { CommandCenter } from "./screens/CommandCenter";
import { Distribute } from "./screens/Distribute";
import { Identity } from "./screens/Identity";
import { Inbox } from "./screens/Inbox";
import { Investigate } from "./screens/Investigate";
import { Ledger } from "./screens/Ledger";
import { Monitor } from "./screens/Monitor";
import { useConsoleStore } from "./store";

export function App() {
  const screen = useConsoleStore((state) => state.screen);
  return <Shell>
    {screen === "command" && <CommandCenter />}
    {screen === "identity" && <Identity />}
    {screen === "distribute" && <Distribute />}
    {screen === "inbox" && <Inbox />}
    {screen === "monitor" && <Monitor />}
    {screen === "investigate" && <Investigate />}
    {screen === "ledger" && <Ledger />}
    {screen === "attacklab" && <AttackLab />}
  </Shell>;
}
