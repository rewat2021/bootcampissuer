# Stage 1: Build
# IssuerAPI.csproj targets net9.0 (<TargetFramework>net9.0</TargetFramework>) — this was pinned to
# the 8.0 SDK image, which fails the build outright (NETSDK1045: this project requires a newer
# version of the .NET SDK). Bumped to 9.0 to match the actual project target.
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# มี subfolder IssuerAPI/ อยู่
COPY ["IssuerAPI/IssuerAPI.csproj", "IssuerAPI/"]
RUN dotnet restore "IssuerAPI/IssuerAPI.csproj"

COPY . .
WORKDIR "/src/IssuerAPI"
RUN dotnet build "IssuerAPI.csproj" -c Release -o /app/build

# Stage 2: Publish
FROM build AS publish
RUN dotnet publish "IssuerAPI.csproj" -c Release -o /app/publish --no-restore

# Stage 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
EXPOSE 8080

COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "IssuerAPI.dll"]