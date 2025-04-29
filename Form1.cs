using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;


namespace HypervisorApp
{


    public partial class Form1 : Form
    {
        public const uint ReadWriteAccess = 0xC0000000;
        public const uint ReadWriteShare = 0x00000003;
        public const uint OpenMode = 0x00000003;
        public IntPtr hDrv;
        public Form1()
        {
            InitializeComponent();

            this.hDrv = WinApi.CreateFile("\\\\.\\MyHypervisor", ReadWriteAccess, ReadWriteShare, IntPtr.Zero, OpenMode, 0, IntPtr.Zero);


        }

        private void Form1_Load(object sender, EventArgs e)
        {


        }
      

        
        private void Form1_KeyPress(object sender, KeyPressEventArgs e)
        {

            VmStart vmStartForm = new VmStart(hDrv, this);
            vmStartForm.Show();
            this.WindowState = FormWindowState.Minimized;
            

        }
    }
    public class WinApi
    {
        // DeviceIocontrol

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(
       IntPtr hDevice,
       uint dwIoControlCode,
       IntPtr lpInBuffer,
       uint nInBufferSize,
       IntPtr lpOutBuffer,
       uint nOutBufferSize,
       out uint lpBytesReturned,
       IntPtr lpOverlapped);


        // CreateFile

       [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(
       string lpFileName,
       uint dwDesiredAccess,
       uint dwShareMode,
       IntPtr lpSecurityAttributes,
       uint dwCreationDisposition,
       uint dwFlagsAndAttributes,
       IntPtr hTemplateFile);

        // CloseHandle
       [DllImport("kernel32.dll", SetLastError = true)]
       public static extern bool CloseHandle(IntPtr hObject);

        public static uint BUILD_CTL_CODE(uint deviceType, uint function, uint method, uint access)
        {
            return (deviceType << 16) | (access << 14) | (function << 2) | method;
        }

    }
}
