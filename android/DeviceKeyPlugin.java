package eu.familymemories.app;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.security.KeyStore;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

// =============================================================================
// DeviceKey — the device storage key of the end-to-end layer, held by the
// Android Keystore (docs/e2e-design.md §3, Etappe 1e).
//
// One AES-256-GCM key per signed-in person, generated INSIDE the Keystore
// (StrongBox when the phone has a security chip) and never exportable. The web
// layer hands it bytes to seal (the account key, the trust store) and gets an
// `iv || ciphertext` blob back to store in IndexedDB. A copy of the app's files
// is therefore useless without this very phone.
//
// AAD is passed through unchanged, so the binding of a blob to its purpose and
// person (fm/ak-wrap/v1 …) stays exactly what the web implementation does.
//
// Generations: 1 (apps up to 1.0.8, no unlock binding) and 2 (AP-Android,
// 14.10.2026: setUnlockedDeviceRequired, Android 9+) are only opened, so
// deviceStore.ts can move their records over, and then forgotten.
//
// Generation 3 (P6, A-01): `seal` uses it, and the binding is no longer a
// guess. Generation 2 fell back to a key WITHOUT the binding on any exception
// and kept it under the same alias for good, invisibly. Now the bound key and
// the fallback have aliases of their own, `seal` reports which one sealed, and
// the fallback is made only when the bound key failed twice — never while the
// phone is locked (a transient refusal there is no reason to give up the
// binding). While a person's records are sealed by the fallback, every seal
// tries the bound key first, so deviceStore.ts moves them over once it works.
// =============================================================================
@CapacitorPlugin(name = "DeviceKey")
public class DeviceKeyPlugin extends Plugin {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String PREFIX = "fm-e2e-dsk-";     // generation 1
    private static final String PREFIX_2 = "fm-e2e-dsk2-";  // generation 2
    private static final String PREFIX_3 = "fm-e2e-dsk3-";  // generation 3, bound to the unlocked phone
    private static final String PREFIX_3U = "fm-e2e-dsk3u-"; // generation 3, fallback without the binding
    private static final Pattern UUID = Pattern.compile("^[0-9a-f-]{36}$");
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    @PluginMethod
    public void available(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("available", true);
        ret.put("strongBox", Build.VERSION.SDK_INT >= 28
            && getContext().getPackageManager().hasSystemFeature("android.hardware.strongbox_keystore"));
        // Android 7–8.1 has no unlock binding at all (A-01).
        ret.put("unlockBinding", Build.VERSION.SDK_INT >= 28);
        call.resolve(ret);
    }

    @PluginMethod
    public void seal(PluginCall call) {
        try {
            String userId = userId(call);
            byte[] data = b64(call, "data");
            byte[] aad = b64(call, "aad");
            Sealing k = sealingKey(userId);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            // The Keystore picks the IV itself (randomized encryption required).
            c.init(Cipher.ENCRYPT_MODE, k.key);
            c.updateAAD(aad);
            byte[] ct = c.doFinal(data);
            byte[] iv = c.getIV();
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            JSObject ret = new JSObject();
            ret.put("blob", Base64.encodeToString(out, Base64.NO_WRAP));
            ret.put("bound", k.bound);
            call.resolve(ret);
        } catch (Exception e) {
            // Codes only, never content (design §8).
            call.reject("seal-failed", e.getClass().getSimpleName());
        }
    }

    @PluginMethod
    public void open(PluginCall call) {
        try {
            String userId = userId(call);
            byte[] blob = b64(call, "blob");
            byte[] aad = b64(call, "aad");
            Integer gen = call.getInt("gen", 1);
            if (gen == null || gen < 1 || gen > 3) throw new IllegalArgumentException("gen");
            String prefix = gen == 1 ? PREFIX : gen == 2 ? PREFIX_2
                : call.getBoolean("bound", true) ? PREFIX_3 : PREFIX_3U;
            SecretKey k = existing(prefix + userId);
            if (k == null || blob.length <= IV_BYTES) {
                call.reject("no-key");
                return;
            }
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, k, new GCMParameterSpec(TAG_BITS, blob, 0, IV_BYTES));
            c.updateAAD(aad);
            byte[] pt = c.doFinal(blob, IV_BYTES, blob.length - IV_BYTES);
            JSObject ret = new JSObject();
            ret.put("data", Base64.encodeToString(pt, Base64.NO_WRAP));
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("open-failed", e.getClass().getSimpleName());
        }
    }

    @PluginMethod
    public void forget(PluginCall call) {
        try {
            String userId = userId(call);
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            // legacyOnly: generations 1 and 2, once nothing is sealed with them;
            // the fallback of generation 3 too once nothing is sealed with it.
            ks.deleteEntry(PREFIX + userId);
            ks.deleteEntry(PREFIX_2 + userId);
            boolean legacyOnly = call.getBoolean("legacyOnly", false);
            if (!legacyOnly || call.getBoolean("unboundToo", false)) ks.deleteEntry(PREFIX_3U + userId);
            if (!legacyOnly) ks.deleteEntry(PREFIX_3 + userId);
            call.resolve();
        } catch (Exception e) {
            call.reject("forget-failed", e.getClass().getSimpleName());
        }
    }

    // -------------------------------------------------------------------------

    private static String userId(PluginCall call) {
        String id = call.getString("userId");
        if (id == null || !UUID.matcher(id).matches()) throw new IllegalArgumentException("userId");
        return id;
    }

    private static byte[] b64(PluginCall call, String name) {
        String v = call.getString(name);
        if (v == null) throw new IllegalArgumentException(name);
        return Base64.decode(v, Base64.NO_WRAP);
    }

    private static final class Sealing {
        final SecretKey key;
        final boolean bound;
        Sealing(SecretKey key, boolean bound) { this.key = key; this.bound = bound; }
    }

    private static SecretKey existing(String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        return ks.containsAlias(alias) ? (SecretKey) ks.getKey(alias, null) : null;
    }

    /**
     * The key `seal` uses: the bound one of generation 3 — made now if need be —
     * and only when that cannot be had, the fallback (A-01).
     */
    private Sealing sealingKey(String userId) throws Exception {
        SecretKey bound = existing(PREFIX_3 + userId);
        if (bound != null) return new Sealing(bound, true);
        Exception refused = null;
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                return new Sealing(generate(PREFIX_3 + userId, true, true), true);
            } catch (StrongBoxUnavailableException e) {
                // No security chip: the regular (TEE) Keystore.
            } catch (Exception e) {
                // A chip that refuses this key: the TEE still carries the binding.
            }
            // Twice — a busy or restarting Keystore service must not cost the binding.
            for (int attempt = 0; attempt < 2; attempt++) {
                try {
                    return new Sealing(generate(PREFIX_3 + userId, false, true), true);
                } catch (Exception e) {
                    refused = e;
                    if (attempt == 0) Thread.sleep(200);
                }
            }
            // Behind the lock screen a refusal says nothing about the phone; the
            // record stays as it is and the next load tries again.
            KeyguardManager km = (KeyguardManager) getContext().getSystemService(Context.KEYGUARD_SERVICE);
            if (km == null || km.isDeviceLocked()) throw refused;
        }
        // Android 7–8.1, or a Keystore that refuses the binding while unlocked:
        // a key without it beats a phone on which E2E cannot be set up.
        SecretKey fallback = existing(PREFIX_3U + userId);
        if (fallback == null) fallback = generate(PREFIX_3U + userId, false, false);
        return new Sealing(fallback, false);
    }

    private static SecretKey generate(String alias, boolean strongBox, boolean unlocked) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true);
        if (Build.VERSION.SDK_INT >= 28) {
            if (strongBox) b.setIsStrongBoxBacked(true);
            // Generations 2 and 3: unusable while the phone is locked (finding j / k).
            if (unlocked) b.setUnlockedDeviceRequired(true);
        }
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        g.init(b.build());
        return g.generateKey();
    }
}
