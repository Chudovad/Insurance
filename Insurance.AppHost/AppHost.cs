var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.Insurance_MiniApp>("insurance-miniapp");

builder.AddProject<Projects.Insurance_API>("insurance-api");

builder.Build().Run();
