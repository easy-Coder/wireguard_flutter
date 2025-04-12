package billion.group.wireguard_flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.PluginRegistry

import android.app.Activity
import io.flutter.embedding.android.FlutterActivity
import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import com.beust.klaxon.Klaxon
import com.wireguard.android.backend.*
import com.wireguard.config.Config
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import io.flutter.plugin.common.EventChannel
import kotlinx.coroutines.*
import java.util.*


import kotlinx.coroutines.launch
import java.io.ByteArrayInputStream
import kotlinx.coroutines.CompletableDeferred

/** WireguardFlutterPlugin */

const val PERMISSIONS_REQUEST_CODE = 10014
const val METHOD_CHANNEL_NAME = "billion.group.wireguard_flutter/wgcontrol"
const val METHOD_EVENT_NAME = "billion.group.wireguard_flutter/wgstage"

class WireguardFlutterPlugin : FlutterPlugin, MethodCallHandler, ActivityAware,
    PluginRegistry.ActivityResultListener {
    private lateinit var channel: MethodChannel
    private lateinit var events: EventChannel
    private lateinit var tunnelName: String
    private val futureBackend = CompletableDeferred<Backend>()
    private var vpnStageSink: EventChannel.EventSink? = null
    private val scope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    private var backend: Backend? = null
    private var havePermission = false
    private lateinit var context: Context
    private var activity: Activity? = null
    private var config: Config? = null
    private var tunnel: WireGuardTunnel? = null
    private val TAG = "NVPN"
    var isVpnChecked = false

    private var permissionResultCallback: Result? = null

    companion object {
        private var state: String = "no_connection"

        fun getStatus(): String {
            return state
        }
    }
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode == PERMISSIONS_REQUEST_CODE) {
            val permissionGranted = resultCode == Activity.RESULT_OK
            this.havePermission = permissionGranted // Update the flag

            // Use the stored callback to complete the initialize call
            permissionResultCallback?.let { callback -> // 'callback' is the Result object here
                if (permissionGranted) {
                    Log.i(TAG, "VPN permission granted.")
                    // Use helper to complete the initialize call successfully
                    flutterSuccess(callback, true)
                } else {
                    Log.w(TAG, "VPN permission denied.")
                    // Use helper to complete the initialize call with an error
                    flutterError(
                        callback,
                        "PERMISSION_DENIED",
                        "VPN permission was not granted by the user."
                    )
                }
                permissionResultCallback = null // Clear the callback once used
            }
            return permissionGranted // Return if the result was handled
        }
        return false
    }

    private var activityPluginBinding: ActivityPluginBinding? = null

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        this.activity = binding.activity as FlutterActivity
        binding.addActivityResultListener(this) // Add listener
        this.activityPluginBinding = binding
    }

    override fun onDetachedFromActivityForConfigChanges() {
        this.activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        this.activity = binding.activity as FlutterActivity
        // Listener should still be attached unless activity was fully detached
        if (this.activityPluginBinding == null) {
            binding.addActivityResultListener(this)
            this.activityPluginBinding = binding
        }
    }

    override fun onDetachedFromActivity() {
        this.activityPluginBinding?.removeActivityResultListener(this) // Remove listener
        this.activityPluginBinding = null
        this.activity = null
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, METHOD_CHANNEL_NAME)
        events = EventChannel(flutterPluginBinding.binaryMessenger, METHOD_EVENT_NAME)
        context = flutterPluginBinding.applicationContext

        scope.launch(Dispatchers.IO) {
            try {
                backend = createBackend()
                futureBackend.complete(backend!!)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }

        channel.setMethodCallHandler(this)
        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                isVpnChecked = false
                vpnStageSink = events
                // Optionally send current state on listen
                vpnStageSink?.success(state.lowercase(Locale.ROOT))
            }

            override fun onCancel(arguments: Any?) {
                isVpnChecked = false
                vpnStageSink = null
            }
        })

    }

    private fun createBackend(): Backend {
        if (backend == null) {
            backend = GoBackend(context)
        }
        return backend as Backend
    }

    private fun flutterSuccess(result: Result, data: Any?) {
        scope.launch(Dispatchers.Main.immediate) {
            result.success(data)
        }
    }

    private fun flutterError(result: Result, errorCode: String, errorMessage: String?, errorDetails: Any? = null) {
        scope.launch(Dispatchers.Main.immediate) {
            result.error(errorCode, errorMessage, errorDetails)
        }
    }

    private fun flutterNotImplemented(result: Result) {
        scope.launch(Dispatchers.Main) {
            result.notImplemented()
        }
    }

    override fun onMethodCall(call: MethodCall, result: Result) {

        when (call.method) {
            "initialize" -> setupTunnel(call.argument<String>("localizedDescription").toString(), result)
            "start" -> {
                connect(call.argument<String>("wgQuickConfig").toString(), result)
            }
            "stop" -> {
                disconnect(result)
            }
            "stage" -> {
                result.success(getStatus())
            }
            "checkPermission" -> {
                checkPermission(result)
                result.success(null)
            }
            "getDownloadData" -> {
                getDownloadData(result)
            }
            "getUploadData" -> {
                getUploadData(result)
            }
            "generateKeyPair" -> {
                generateKeyPair(result)
            }
            else -> flutterNotImplemented(result)
        }
    }

    private fun isVpnActive(): Boolean {
        try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = connectivityManager.activeNetwork
                val networkCapabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
                return networkCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            } else {
                return false
            }
        } catch (e: Exception) {
            Log.e(TAG, "isVpnActive - ERROR - ${e.message}")
            return false
        }
    }

    private fun updateStage(stage: String?) {
        scope.launch(Dispatchers.Main) {
            val updatedStage = stage ?: "no_connection"
            state = updatedStage
            vpnStageSink?.success(updatedStage.lowercase(Locale.ROOT))
        }
    }

    private fun updateStageFromState(state: Tunnel.State) {
        scope.launch(Dispatchers.Main) {
            when (state) {
                Tunnel.State.UP -> updateStage("connected")
                Tunnel.State.DOWN -> updateStage("disconnected")
                else -> updateStage("wait_connection")
            }
        }
    }

    private fun disconnect(result: Result) {
        if (!::tunnelName.isInitialized || tunnelName.isEmpty()) {
            flutterError(result, "TUNNEL_NOT_INITIALIZED", "Tunnel not initialized. Call initialize first.")
            return
        }
        scope.launch(Dispatchers.IO) { // Runs on IO thread
            try {

                val currentTunnel = tunnel(tunnelName) { state ->
                    scope.launch(Dispatchers.Main) {
                        Log.i(TAG, "onStateChange - $state")
                        updateStageFromState(state)
                    }
                }

                if (futureBackend.await().runningTunnelNames.contains(currentTunnel.getName())) {
                    updateStage("disconnecting")
                    futureBackend.await().setState(currentTunnel, Tunnel.State.DOWN, config)
                    Log.i(TAG, "Disconnect - success!")
                    flutterSuccess(result, "") // Use helper
                } else {
                    Log.w(TAG, "Disconnect - Tunnel '$tunnelName' is not running.")
                    updateStage("disconnected")
                    flutterSuccess(result, "")
                }

            } catch (e: BackendException) {
                Log.e(TAG, "Disconnect - BackendException - ERROR - ${e.reason}", e)
                updateStage("disconnected") // Update stage on failure
                // Use helper with BackendException reason as code
                flutterError(result, e.reason.toString(), "Disconnection failed: ${e.reason}")

            } catch (e: Throwable) {
                Log.e(TAG, "Disconnect - Can't disconnect from tunnel: ${e.message}", e)
                updateStage("disconnected") // Update stage on failure
                // Use helper with generic error code
                flutterError(result, "DISCONNECT_ERROR", "Disconnection failed: ${e.message}")
            }
        }
    }

    private fun connect(wgQuickConfig: String, result: Result) {
        if (!::tunnelName.isInitialized || tunnelName.isEmpty()) {
            flutterError(result, "TUNNEL_NOT_INITIALIZED", "Tunnel not initialized. Call initialize first.")
            return
        }
        scope.launch(Dispatchers.IO) { // Runs on IO thread
            try {
                updateStage("prepare")
                val inputStream = ByteArrayInputStream(wgQuickConfig.toByteArray())
                config = com.wireguard.config.Config.parse(inputStream)

                val currentTunnel = tunnel(tunnelName) { state ->
                    scope.launch(Dispatchers.Main) {
                        Log.i(TAG, "onStateChange - $state")
                        updateStageFromState(state)
                    }
                }

                updateStage("connecting")
                futureBackend.await().setState(currentTunnel, Tunnel.State.UP, config)

                Log.i(TAG, "Connect - success!")
                flutterSuccess(result, "")

            } catch (e: BackendException) {
                Log.e(TAG, "Connect - BackendException - ERROR - ${e.reason}", e)
                updateStage("disconnected")
                flutterError(result, e.reason.toString(), "Connection failed: ${e.reason}")

            } catch (e: Throwable) {
                Log.e(TAG, "Connect - Can't connect to tunnel: $e", e)
                updateStage("disconnected")
                flutterError(result, "CONNECT_ERROR", "Connection failed: ${e.message}")
            }
        }
    }

    private fun setupTunnel(localizedDescription: String, result: Result) {
        if (Tunnel.isNameInvalid(localizedDescription)) {
            // Use helper for immediate error
            flutterError(result, "INVALID_NAME", "Tunnel name is invalid")
            return
        }
        this.tunnelName = localizedDescription

        val intent = GoBackend.VpnService.prepare(this.activity)
        if (intent != null) {
            // Permission is required
            havePermission = false
            if (this.activity == null) {
                flutterError(result, "ACTIVITY_NULL", "Cannot request permission without activity context.")
                return
            }

            this.permissionResultCallback = result
            try {
                this.activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
                Log.i(TAG, "VPN permission request initiated.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start activity for result", e)
                this.permissionResultCallback = null
                flutterError(result, "ACTIVITY_START_FAILED", "Could not start permission activity: ${e.message}")
            }

        } else {
            havePermission = true
            Log.i(TAG, "VPN permission already granted.")
            flutterSuccess(result, true)
        }
    }

    private fun checkPermission(result: Result) {
        val intent = GoBackend.VpnService.prepare(this.activity)
        if (intent != null) {
            // Permission is required
            havePermission = false
            if (this.activity == null) {
                flutterError(result, "ACTIVITY_NULL", "Cannot request permission without activity context.")
                return
            }

            this.permissionResultCallback = result
            try {
                this.activity?.startActivityForResult(intent, PERMISSIONS_REQUEST_CODE)
                Log.i(TAG, "VPN permission request initiated.")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start activity for result", e)
                this.permissionResultCallback = null
                flutterError(result, "ACTIVITY_START_FAILED", "Could not start permission activity: ${e.message}")
            }

        } else {
            havePermission = true
            Log.i(TAG, "VPN permission already granted.")
            flutterSuccess(result, true)
        }
    }

    private fun getDownloadData(result: Result) {
        if (!::tunnelName.isInitialized || tunnelName.isEmpty()) {
            flutterError(result, "TUNNEL_NOT_INITIALIZED", "Tunnel not initialized. Call initialize first.")
            return
        }
        scope.launch(Dispatchers.IO) { // Runs on IO thread
            try {
                // Ensure tunnel object exists for the call
                val currentTunnel = tunnel(tunnelName)
                val downloadData = futureBackend.await().getStatistics(currentTunnel).totalRx()
                flutterSuccess(result, downloadData) // Use helper
            } catch (e: Throwable) {
                Log.e(TAG, "getDownloadData - ERROR - ${e.message}", e)
                // Use helper with error code
                flutterError(result, "GET_DATA_ERROR", "Failed to get download data: ${e.message}")
            }
        }
    }

    private fun getUploadData(result: Result) {
        if (!::tunnelName.isInitialized || tunnelName.isEmpty()) {
            flutterError(result, "TUNNEL_NOT_INITIALIZED", "Tunnel not initialized. Call initialize first.")
            return
        }
        scope.launch(Dispatchers.IO) { // Runs on IO thread
            try {
                // Ensure tunnel object exists for the call
                val currentTunnel = tunnel(tunnelName)
                val uploadData = futureBackend.await().getStatistics(currentTunnel).totalTx()
                flutterSuccess(result, uploadData) // Use helper
            } catch (e: Throwable) {
                Log.e(TAG, "getDownloadData - ERROR - ${e.message}", e)
                // Use helper with error code
                flutterError(result, "GET_DATA_ERROR", "Failed to get download data: ${e.message}")
            }
        }
    }

    private fun generateKeyPair(result: Result) {
        val keyPair = KeyPair()
        result.success(
            hashMapOf(
                "privateKey" to keyPair.privateKey.toBase64(),
                "publicKey" to keyPair.publicKey.toBase64()
            )
        )
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        events.setStreamHandler(null)
        vpnStageSink = null // Clean up sink
        permissionResultCallback = null // Clean up callback
        scope.cancel() // Cancel coroutines
        isVpnChecked = false
    }

    private fun tunnel(name: String, callback: StateChangeCallback? = null): WireGuardTunnel {
        if (tunnel == null) {
            tunnel = WireGuardTunnel(name, callback)
        }
        return tunnel as WireGuardTunnel
    }
}

typealias StateChangeCallback = (Tunnel.State) -> Unit

class WireGuardTunnel(
    private val name: String, private val onStateChanged: StateChangeCallback? = null
) : Tunnel {

    override fun getName() = name

    override fun onStateChange(newState: Tunnel.State) {
        onStateChanged?.invoke(newState)
    }

}
