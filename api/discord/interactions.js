// api/discord/interactions.js
const nacl = require('tweetnacl');
const { waitUntil } = require('@vercel/functions');

const ALLOWED_USERNAMES = ['bacony3311', 'primscokie', 'huh_hmmm', 'cold.iceee'];

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

  const clickerUsername =
    (body.member && body.member.user && body.member.user.username) ||
    (body.user && body.user.username) ||
    '';
  const isTrustedClicker = ALLOWED_USERNAMES.some(
    (u) => u.toLowerCase() === clickerUsername.toLowerCase()
  );

  const customId = body.data && typeof body.data.custom_id === 'string' ? body.data.custom_id : '';

  // --- Button: Unban ---------------------------------------------------
  if (body.type === 3 && customId.startsWith('unban_')) {
    const playFabId = customId.slice('unban_'.length);

    if (!isTrustedClicker) {
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to unban players.`, flags: 64 }
      });
    }

    // ACK within Discord's 3s window.
    res.status(200).json({ type: 5, data: { flags: 64 } });

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

  // --- Button: Change Ban Reason -> opens a modal ----------------------
  if (body.type === 3 && customId.startsWith('changereason_')) {
    const playFabId = customId.slice('changereason_'.length);

    if (!isTrustedClicker) {
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to change ban reasons.`, flags: 64 }
      });
    }

    return res.status(200).json({
      type: 9,
      data: {
        custom_id: `reasonmodal_${playFabId}`,
        title: 'Change ban reason',
        components: [
          {
            type: 1,
            components: [
              {
                type: 4,
                custom_id: 'new_reason',
                style: 2,
                label: 'New ban reason',
                min_length: 1,
                max_length: 450,
                required: true,
                placeholder: 'Why should this player actually be banned?'
              }
            ]
          }
        ]
      }
    });
  }

  // --- Modal submit: Change Ban Reason ---------------------------------
  if (body.type === 5 && customId.startsWith('reasonmodal_')) {
    const playFabId = customId.slice('reasonmodal_'.length);

    if (!isTrustedClicker) {
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to change ban reasons.`, flags: 64 }
      });
    }

    const textInputRow = (body.data.components || [])[0];
    const rawNewReason = textInputRow && textInputRow.components && textInputRow.components[0] && textInputRow.components[0].value;
    const newReason = (rawNewReason || '').trim();

    if (!newReason) {
      return res.status(200).json({
        type: 4,
        data: { content: 'New reason can\'t be empty.', flags: 64 }
      });
    }

    res.status(200).json({ type: 5, data: { flags: 64 } });

    waitUntil(
      (async () => {
        const result = await callChangeBanReasonCloudScript(playFabId, newReason, clickerUsername);

        await editOriginalResponse(body.application_id, body.token, {
          content: result.Success
            ? `✅ Ban reason for \`${playFabId}\` updated by ${clickerUsername}.\n**New reason:** ${result.NewReason}`
            : `❌ Failed to change ban reason: ${result.Message}`
        });
      })()
    );

    return;
  }

  // --- Button: Change Ban Duration -> opens a modal --------------------
  if (body.type === 3 && customId.startsWith('changeduration_')) {
    const playFabId = customId.slice('changeduration_'.length);

    if (!isTrustedClicker) {
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to change ban durations.`, flags: 64 }
      });
    }

    return res.status(200).json({
      type: 9,
      data: {
        custom_id: `durationmodal_${playFabId}`,
        title: 'Change ban duration',
        components: [
          {
            type: 1,
            components: [
              {
                type: 4,
                custom_id: 'new_duration',
                style: 1, // short
                label: 'New duration (from now)',
                min_length: 1,
                max_length: 20,
                required: true,
                placeholder: 'e.g. 48h, 7d, 2w, or perm'
              }
            ]
          }
        ]
      }
    });
  }

  // --- Modal submit: Change Ban Duration -------------------------------
  if (body.type === 5 && customId.startsWith('durationmodal_')) {
    const playFabId = customId.slice('durationmodal_'.length);

    if (!isTrustedClicker) {
      return res.status(200).json({
        type: 4,
        data: { content: `${clickerUsername || 'You'} aren't authorized to change ban durations.`, flags: 64 }
      });
    }

    const textInputRow = (body.data.components || [])[0];
    const rawDuration = textInputRow && textInputRow.components && textInputRow.components[0] && textInputRow.components[0].value;
    const newDuration = (rawDuration || '').trim();

    if (!newDuration) {
      return res.status(200).json({
        type: 4,
        data: { content: 'Duration can\'t be empty.', flags: 64 }
      });
    }

    res.status(200).json({ type: 5, data: { flags: 64 } });

    waitUntil(
      (async () => {
        const result = await callChangeBanDurationCloudScript(playFabId, newDuration, clickerUsername);

        await editOriginalResponse(body.application_id, body.token, {
          content: result.Success
            ? `✅ Ban duration for \`${playFabId}\` updated by ${clickerUsername}.\n**New duration:** ${result.DurationLabel}`
            : `❌ Failed to change ban duration: ${result.Message}`
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

async function callCloudScript(functionName, functionParameter, playFabId) {
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
        FunctionName: functionName,
        FunctionParameter: functionParameter,
        GeneratePlayStreamEvent: false
      })
    });

    const json = await response.json();
    console.log(`[${functionName}] PlayFab raw response:`, JSON.stringify(json));
    if (json.data && json.data.Error) {
      return { Success: false, Message: json.data.Error.Message || 'CloudScript error.' };
    }
    return (json.data && json.data.FunctionResult) || { Success: false, Message: 'No result from CloudScript.' };
  } catch (e) {
    return { Success: false, Message: 'Request to PlayFab failed: ' + e.message };
  }
}

function callUnbanCloudScript(playFabId, discordUsername) {
  return callCloudScript('UnbanFromDiscord', {
    PlayFabId: playFabId,
    DiscordUsername: discordUsername,
    Secret: process.env.UNBAN_ACTION_SECRET
  }, playFabId);
}

function callChangeBanReasonCloudScript(playFabId, newReason, discordUsername) {
  return callCloudScript('ChangeBanReason', {
    PlayFabId: playFabId,
    NewReason: newReason,
    DiscordUsername: discordUsername,
    Secret: process.env.UNBAN_ACTION_SECRET
  }, playFabId);
}

function callChangeBanDurationCloudScript(playFabId, newDuration, discordUsername) {
  return callCloudScript('ChangeBanDuration', {
    PlayFabId: playFabId,
    NewDuration: newDuration,
    DiscordUsername: discordUsername,
    Secret: process.env.UNBAN_ACTION_SECRET
  }, playFabId);
}

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
