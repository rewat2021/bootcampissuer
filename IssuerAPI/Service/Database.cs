using IssuerAPI.Models;
using IssuerAPI.Service;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

namespace IssuerAPI
{
    public static class Table
    {
        public const string General = "General";
        public const string Home = "Home";
        public const string Operations = "Operations";
        public const string Procedures = "Procedures";
        public const string Testcase = "Testcase";
    }
    public static class Database
    {
        private static readonly string DataPath = Path.Combine(Environment.CurrentDirectory,"Data");
        public static void Write(string table, string key,string value, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key+".txt");

            using (var sw = new StreamWriter(path))
            {
                sw.Write(value);
            }
        }
        public static string Read(string table, string key, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key + ".txt");
            try
            {
                string lines = File.ReadAllText(path);
                return lines;
            }
            catch(Exception ex)
            {
                return "";
            }
        }

        public static string ReadDID(string table, string key, IWebHostEnvironment env)
        {
            var path = Path.Combine(env.ContentRootPath, key + ".txt");
            try
            {
                string lines = File.ReadAllText(path);
                return lines;
            }
            catch (Exception ex)
            {
                return "";
            }
        }

       
    }
}
