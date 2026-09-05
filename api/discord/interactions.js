// api/discord/interactions.js
const nacl = require('tweetnacl');
const { waitUntil } = require('@vercel/functions');

const ALLOWED_USERNAMES = ['bacony3311', 'primscokie', 'huh_hmmm'];

module.exports.config = {
  api: { bodyParser: false }
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

  if (body.type === 1) {
    return res.status(200).json({ type: 1 });
  }

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
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to unban players.`, flags: 64 }
      });
    }

    // ACK within Discord's 3s window.
    res.status(200).json({ type: 5, data: { flags: 64 } });

    // Vercel can freeze the function right after the response above is
    // flushed - waitUntil() keeps it alive until this promise settles,
    // so the PlayFab call + Discord PATCH actually get to run.
    waitUntil(
      (async () => {
        const result = await callUnbanCloudScript(playFabId, clickerUsername);

        await editOriginalResponse(body.application_id, body.token, {
          content: result.Success
            ? `✅ \`${playFabId}\` was unbanned by ${clickerUsername}.`
            : `❌ Unban failed: ${result.Message}`
        });
      })()
    );

    return;
  }

  return res.status(400).send('unhandled interaction type');
};

async function editOriginalResponse(applicationId, interactionToken, data) {
  try {
    await fetch(
      `https://discord.com/api/v10/webhooks/${applicationId}/${interactionToken}/messages/@original`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      }
    );
  } catch (e) {
    console.error('Failed to edit original interaction response:', e.message);
  }
}

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
