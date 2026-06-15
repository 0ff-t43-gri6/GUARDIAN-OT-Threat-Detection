const { OPCUAServer, Variant, DataType, StatusCodes } = require("node-opcua");

async function startServer() {
    const server = new OPCUAServer({
        port: 4840,
        resourcePath: "/UA/SimulationServer",
        buildInfo: {
            productName: "OT-Simulation-Server",
            buildNumber: "1",
            buildDate: new Date()
        },
        securityModes: [1],
        securityPolicies: [1],
        allowAnonymous: true
    });

    await server.initialize();

    const addressSpace = server.engine.addressSpace;
    const namespace = addressSpace.getOwnNamespace();

    const processFolder = namespace.addFolder("RootFolder", {
        browseName: "ProcessData"
    });

    // Temperature
    let temperature = 75.0;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "Temperature",
        nodeId: "ns=1;s=Temperature",
        dataType: "Double",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Double, value: temperature }),
            set: (variant) => { temperature = variant.value; return StatusCodes.Good; }
        }
    });

    // Pressure
    let pressure = 101.3;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "Pressure",
        nodeId: "ns=1;s=Pressure",
        dataType: "Double",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Double, value: pressure }),
            set: (variant) => { pressure = variant.value; return StatusCodes.Good; }
        }
    });

    // Motor Speed
    let motorSpeed = 1450.0;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "MotorSpeed",
        nodeId: "ns=1;s=MotorSpeed",
        dataType: "Double",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Double, value: motorSpeed }),
            set: (variant) => { motorSpeed = variant.value; return StatusCodes.Good; }
        }
    });

    // Valve Position
    let valvePosition = 45.0;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "ValvePosition",
        nodeId: "ns=1;s=ValvePosition",
        dataType: "Double",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Double, value: valvePosition }),
            set: (variant) => { valvePosition = variant.value; return StatusCodes.Good; }
        }
    });

    // Pump Status
    let pumpStatus = true;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "PumpStatus",
        nodeId: "ns=1;s=PumpStatus",
        dataType: "Boolean",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Boolean, value: pumpStatus }),
            set: (variant) => { pumpStatus = variant.value; return StatusCodes.Good; }
        }
    });

    // Flow Rate
    let flowRate = 32.5;
    namespace.addVariable({
        componentOf: processFolder,
        browseName: "FlowRate",
        nodeId: "ns=1;s=FlowRate",
        dataType: "Double",
        minimumSamplingInterval: 1000,
        value: {
            get: () => new Variant({ dataType: DataType.Double, value: flowRate }),
            set: (variant) => { flowRate = variant.value; return StatusCodes.Good; }
        }
    });

    // Simulate live changing values
    setInterval(() => {
        temperature   += (Math.random() - 0.5) * 2;
        pressure      += (Math.random() - 0.5) * 0.5;
        motorSpeed    += (Math.random() - 0.5) * 10;
        flowRate      += (Math.random() - 0.5) * 1.5;
    }, 1000);

    await server.start();

    console.log("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=");
    console.log("  GUARDIAN OT Simulation Server — RUNNING");
    console.log("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
    console.log(`  Endpoint : opc.tcp://localhost:4840/UA/SimulationServer`);
    console.log(`  Security : NONE (lab mode)`);
    console.log(`  Auth     : Anonymous ENABLED`);
    console.log("----------------------------------------------");
    console.log("  Simulated Tags:");
    console.log("    ns=1;s=Temperature   → Temperature (°C)");
    console.log("    ns=1;s=Pressure      → Pressure (kPa)");
    console.log("    ns=1;s=MotorSpeed    → Motor RPM");
    console.log("    ns=1;s=ValvePosition → Valve % open");
    console.log("    ns=1;s=PumpStatus    → Pump ON/OFF");
    console.log("    ns=1;s=FlowRate      → Flow Rate (L/min)");
    console.log("==============================================");
    console.log("  Press Ctrl+C to stop");
}

startServer().catch(console.error);
