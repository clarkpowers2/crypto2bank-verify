`import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

// Use ONE of these (recommended: HMAC signature)
const SHARED_SECRET = process.env.GUARDIAN_BRIDGE_SECRET; // same value in GitHub Actions secret

function timingSafeEq(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifySignature(req) {
  const sig = req.header("x-guardian-signature") || "";
  const body = JSON.stringify(req.body ?? {});
  const expected = crypto.createHmac("sha256", SHARED_SECRET).update(body).digest("hex");
  return timingSafeEq(sig, expected);
}

app.post("/bridge/guardian", async (req, res) => {
  if (!SHARED_SECRET) return res.status(500).json({ ok: false, error: "Missing server secret" });
  if (!verifySignature(req)) return res.status(401).json({ ok: false, error: "Bad signature" });

  const { event, repo, sha, ref, actor } = req.body;

  // TODO: do the work you want (deploy, run scripts, call Supabase, etc.)
  console.log("Bridge hit:", { event, repo, sha, ref, actor });

  return res.json({ ok: true, message: "Bridge received", received: { event, repo, sha, ref, actor } });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Bridge listening on", port));

