# Simple Actor Model

Here’s a rough mental model of how you might build a simple, lightweight actor-like system using nothing but Tokio’s async/await and message channels (or futures channels). The idea is:
	1.	Each “actor” is just an async task (a loop) that listens on a channel for incoming messages.
	2.	You communicate with that “actor” by sending it messages over the channel.
	3.	If you need a reply, you can bundle a oneshot sender into your message.

Because this doesn’t rely on any advanced runtime features or multi-threading, it can work in both native and browser-based WASM environments (with the usual caveats that blocking calls will freeze the single-threaded WASM event loop).

Below is an example of a minimal approach.

Example Actor Definition

use tokio::sync::{mpsc, oneshot};

// Define the messages our actor can handle
pub enum MyActorMsg {
    // Simple message, no response needed
    PrintHello,
    // Request/response message with a oneshot channel for returning a value
    EchoRequest(String, oneshot::Sender<String>),
}

// This is our actor "handle" – the object we give out to others so they can send messages
#[derive(Clone)]
pub struct MyActorHandle {
    sender: mpsc::Sender<MyActorMsg>,
}

impl MyActorHandle {
    /// Example function that sends a one-way message
    pub async fn print_hello(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.sender.send(MyActorMsg::PrintHello).await?;
        Ok(())
    }

    /// Example function that sends a request and awaits a response
    pub async fn echo(&self, text: &str) -> Result<String, Box<dyn std::error::Error>> {
        let (resp_tx, resp_rx) = oneshot::channel();

        self.sender
            .send(MyActorMsg::EchoRequest(text.to_string(), resp_tx))
            .await?;

        // Wait for the response
        let reply = resp_rx.await?;
        Ok(reply)
    }
}

/// Spawn the actor's "main loop" as a background task.
/// Returns a handle that others can use to communicate with the actor.
pub fn spawn_my_actor() -> MyActorHandle {
    // Channel for incoming messages
    let (tx, mut rx) = mpsc::channel::<MyActorMsg>(32);

    // Spawn an async task that processes incoming messages
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            match msg {
                MyActorMsg::PrintHello => {
                    // Do something with the message
                    web_sys::console::log_1(&"Hello from MyActor".into());
                }
                MyActorMsg::EchoRequest(input, reply_tx) => {
                    let output = format!("Echoing: {}", input);
                    // Send the response back
                    let _ = reply_tx.send(output);
                }
            }
        }
    });

    // Give out the handle for sending messages
    MyActorHandle { sender: tx }
}

Using the Actor

#[tokio::main] // or single-threaded builder for WASM
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let actor = spawn_my_actor();

    // Send a one-way message
    actor.print_hello().await?;

    // Send a request and wait for the reply
    let echo_result = actor.echo("Hello WASM").await?;
    println!("Got reply: {}", echo_result);

    Ok(())
}

Making It Work in Both Native and WASM
	1.	Use a Single-Thread or Current-Thread Runtime for WASM
In a browser, you typically won’t have the standard multi-threaded capabilities. If you’re using Tokio, you need something like:

[dependencies]
tokio = { version = "1", features = ["rt", "macros", "sync"] }

And then you can either:
- [ ]	Use #[tokio::main(flavor = "current_thread")] in your main or test code, or
- [ ]	Manually build a single-thread runtime with:

tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();


	2.	Conditional Compilation
If you need a different runtime approach for native vs. WASM, you can use conditional attributes:

#[cfg(target_arch = "wasm32")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // ...
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    // ...
}

But in many cases, a single-threaded Tokio runtime also works fine natively (just not as performant if you wanted multi-threading). So you can keep it the same if you don’t mind single-threaded operation on native as well.

	3.	Non-Blocking & No Thread Assumptions
Don’t call blocking functions like std::thread::sleep in your actor loop. Use async timers, e.g. tokio::time::sleep, which will work in the browser environment.
	4.	No Shared Mutable State
If you’re used to multi-threaded concurrency, be aware that in WASM’s main thread, you’re effectively single-threaded. The actor model still helps keep your code organized, but if you wanted parallelism you’d need web workers—which is an entirely different approach (and means separate WASM instances with message passing across workers).

Why This Approach?
	1.	Simplicity
You don’t need a full actor framework—just a structured way to spawn tasks that handle messages. This approach works pretty much the same on native and WASM.
	2.	Seamless API
The “handle” struct is easy to pass around. Functions on the handle do the boilerplate of creating oneshot channels for responses and sending the message. Anyone who has the MyActorHandle can interact with your actor.
	3.	Extensible
You can define additional messages to handle new tasks, or spawn multiple actors and pass handles around for modular design.
	4.	Easy Testing
You can spin up the actor in unit tests (on native) and verify its behavior. WASM tests can work as well, although WASM testing can be a bit more involved.

In Summary
- [ ]	Define a struct for your “messages” or commands.
- [ ]	For each actor, spawn a single async task that receives messages in a loop.
- [ ]	Expose an API (handle) for sending messages and optionally awaiting a response.
- [ ]	Make sure you use a WASM-friendly (non-blocking, single-threaded) runtime configuration.
- [ ]	You can run the same code on native and in the browser with only minor changes (if any) for setting up Tokio’s runtime.

This keeps your actor model lightweight and portable without pulling in the full machinery of Actix or other actor frameworks, which can sometimes assume or expect multi-threading. As long as you’re comfortable with the fundamental constraints of a single-threaded environment in the browser, this is often all you need to get a nice asynchronous “actor-ish” architecture in both WASM and native.

lightweight actor system. Each item is a single-point task for a coding agent:
- [ ]	Create an enum for the actor’s message types, including any request/response patterns.
- [ ]	Implement a handle struct (e.g., MyActorHandle) containing an mpsc::Sender for message sending.
- [ ]	Write a spawn function (e.g., spawn_my_actor) that:
	1.	Creates an mpsc::channel.
	2.	Spawns an async task that loops to receive messages.
	3.	Processes each message accordingly.
	4.	Returns the handle struct.
- [ ]	Add helper methods to the handle struct to simplify sending messages and awaiting responses (oneshot channels).
- [ ]	Implement a main function that:
	1.	Initializes a Tokio single-thread runtime (to ensure WASM compatibility).
	2.	Spawns the actor.
	3.	Demonstrates sending messages and awaiting responses.
- [ ]	Add conditional compilation if necessary (cfg(target_arch = "wasm32")) to handle WASM vs. native differences (e.g., runtime initialization).
- [ ]	Compile and test natively to confirm expected behavior (print logs, check echo responses, etc.).
- [ ]	Compile to WASM (using wasm-pack or a similar tool) and run in a browser to validate that everything works in a single-threaded environment.
- [ ]	Document usage (e.g., quickstart instructions for other devs or future reference).