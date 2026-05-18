# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
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
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
EXPOSE 8080

COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "IssuerAPI.dll"]