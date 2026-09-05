// api/discord/interactions.js
//
// This is the piece a webhook alone can't provide: Discord only sends a
// click event to a URL you register once, as your app's "Interactions
// Endpoint URL" in the Discord Developer Portal (under your bot's
// Application settings). Deploy this next to your existing
// pt-auth.vercel.app routes (e.g. as /api/discord/interactions), then set
// that deployed URL as the Interactions Endpoint URL for your bot's app.
//
// Required env vars:
//   DISCORD_PUBLIC_KEY     - from the Discord Developer Portal, General tab
//   PLAYFAB_TITLE_ID       - your PlayFab title id
//   PLAYFAB_DEV_SECRET_KEY - a PlayFab developer secret key (Server API access)
//   UNBAN_ACTION_SECRET    - must match UNBAN_ACTION_SECRET in cloudscript.js
//
// npm install tweetnacl

const nacl = require('tweetnacl');

// Match UNBAN_TRUSTED_USERNAMES in cloudscript.js. These are Discord
// *usernames* (the @handle), not server nicknames/display names - Discord
// usernames can change, so if someone renames their account this list needs
// updating too. If you'd rather key off something stable, use Discord user
// IDs instead (body.member.user.id) and update both sides accordingly.
const ALLOWED_USERNAMES = ['bacony3311', 'primscokie', 'huh_hmmm'];

module.exports.config = {
  api: { bodyParser: false } // Discord's signature check needs the raw body
};

module.exports = async (req, res) => {
  const signature = req.headers['x-signature-ed25519'];
  const timestamp = req.headers['x-signature-timestamp'];
  const rawBody = await getRawBody(req);

  if (!signature || !timestamp) {
    return res.status(401).send('missing signature headers');
  }

  const isValid = nacl.sign.detached.verify(
    Buffer.from(timestamp + rawBody),
    Buffer.from(signature, 'hex'),
    Buffer.from(process.env.DISCORD_PUBLIC_KEY, 'hex')
  );
  if (!isValid) {
    return res.status(401).send('invalid request signature');
  }

  const body = JSON.parse(rawBody);

  // Discord's periodic health-check ping - must ack with type 1.
  if (body.type === 1) {
    return res.status(200).json({ type: 1 });
  }

  // Message component interaction (button click) - type 3.
  if (body.type === 3 && body.data && typeof body.data.custom_id === 'string' && body.data.custom_id.startsWith('unban_')) {
    const playFabId = body.data.custom_id.slice('unban_'.length);
    const clickerUsername =
      (body.member && body.member.user && body.member.user.username) ||
      (body.user && body.user.username) ||
      '';

    const isAllowed = ALLOWED_USERNAMES.some(
      (u) => u.toLowerCase() === clickerUsername.toLowerCase()
    );

    if (!isAllowed) {
      // type 4 = respond immediately with a message only the clicker sees (flags: 64 = ephemeral)
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to unban players.`, flags: 64 }
      });
    }

    const result = await callUnbanCloudScript(playFabId, clickerUsername);

    return res.status(200).json({
      type: 4,
      data: {
        content: result.Success
          ? `✅ \`${playFabId}\` was unbanned by ${clickerUsername}.`
          : `❌ Unban failed: ${result.Message}`,
        flags: 64
      }
    });
  }

  return res.status(400).send('unhandled interaction type');
};

async function callUnbanCloudScript(playFabId, discordUsername) {
  const titleId = process.env.PLAYFAB_TITLE_ID;
  const secretKey = process.env.PLAYFAB_DEV_SECRET_KEY;

  try {
    const response = await fetch(`https://${titleId}.playfabapi.com/Server/ExecuteCloudScript`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecretKey': secretKey
      },
      body: JSON.stringify({
        PlayFabId: playFabId,
        FunctionName: 'UnbanFromDiscord',
        FunctionParameter: {
          PlayFabId: playFabId,
          DiscordUsername: discordUsername,
          Secret: process.env.UNBAN_ACTION_SECRET
        },
        GeneratePlayStreamEvent: false
      })
    });

    const json = await response.json();
    if (json.data && json.data.Error) {
      return { Success: false, Message: json.data.Error.Message || 'CloudScript error.' };
    }
    return (json.data && json.data.FunctionResult) || { Success: false, Message: 'No result from CloudScript.' };
  } catch (e) {
    return { Success: false, Message: 'Request to PlayFab failed: ' + e.message };
  }
}

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
