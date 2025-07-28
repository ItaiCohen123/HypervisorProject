using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HypervisorApp
{
    public partial class VM : Form
    {
        // defenition for IOCTL
        public const uint METHOD_BUFFERED = 0;
        public const uint FILE_DEVICE_UNKNOWN = 0X22;
        public const uint FUNCTION = 0x802;
        public const uint FILE_ANY_ACCESS = 0;


        public IntPtr hDrv;
        public IntPtr pCurrActive;
        public Label currActiveVmsLabel;
        public int proccessId;
        public VirtualMachine vm;

        public VM(IntPtr hDrv, int proccessId, IntPtr currActive, Label currActiveVmsLabel, VirtualMachine vm)
        {
            InitializeComponent();
            this.hDrv = hDrv;
            this.proccessId = proccessId;
            this.pCurrActive = currActive;
            this.currActiveVmsLabel = currActiveVmsLabel;
            this.vm = vm;
        }

        private void VM_Load(object sender, EventArgs e)
        {

        }

        private void closeVmButton_Click(object sender, EventArgs e)
        {

            /*
             * 
             * code here telling hypervisor to close the vm
             * 
             */

            string message = "CLOSEVM";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            IntPtr inputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            Marshal.Copy(messageBytes, 0, inputBuffer, messageBytes.Length);
            IntPtr outputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            uint bytesReturned;


            bool result = WinApi.DeviceIoControl(
                hDrv,
                WinApi.BUILD_CTL_CODE(FILE_DEVICE_UNKNOWN, FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS),
                inputBuffer,
                (uint)messageBytes.Length,
                outputBuffer,
                (uint)messageBytes.Length,
                out bytesReturned,
                IntPtr.Zero
                );



            // decrease number by one cause one vm closed
            Marshal.WriteInt32(pCurrActive, Marshal.ReadInt32(pCurrActive) - 1);

            this.currActiveVmsLabel.Text = $"Active: {Marshal.ReadInt32(pCurrActive)}";

            this.vm.DeactiveLable();


            this.Close();
        }

        private void NopButton_Click(object sender, EventArgs e)
        {
            string message = "NOP";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            IntPtr inputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            Marshal.Copy(messageBytes, 0, inputBuffer, messageBytes.Length);
            IntPtr outputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            uint bytesReturned;


            bool result = WinApi.DeviceIoControl(
                hDrv,
                WinApi.BUILD_CTL_CODE(FILE_DEVICE_UNKNOWN, FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS),
                inputBuffer,
                (uint)messageBytes.Length,
                outputBuffer,
                (uint)messageBytes.Length,
                out bytesReturned,
                IntPtr.Zero
                );

            timeStampButton.Enabled = false;
            NopButton.Enabled = false;
            XorButton.Enabled = false;
            AddButton.Enabled = false;



            this.vm.functionChosen = "NOP";
            this.vm.CreateLable();

        }

        private void timeStampButton_Click(object sender, EventArgs e)
        {
            string message = "RDTS";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            IntPtr inputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            Marshal.Copy(messageBytes, 0, inputBuffer, messageBytes.Length);
            IntPtr outputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            uint bytesReturned;


            bool result = WinApi.DeviceIoControl(
                hDrv,
                WinApi.BUILD_CTL_CODE(FILE_DEVICE_UNKNOWN, FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS),
                inputBuffer,
                (uint)messageBytes.Length,
                outputBuffer,
                (uint)messageBytes.Length,
                out bytesReturned,
                IntPtr.Zero
                );

            timeStampButton.Enabled = false;
            NopButton.Enabled = false;
            XorButton.Enabled = false;
            AddButton.Enabled = false;



            this.vm.functionChosen = "Read Time Stamp";
            this.vm.CreateLable();
        }
        private void XorButton_Click(object sender, EventArgs e)
        {
            string message = "XOR";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            IntPtr inputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            Marshal.Copy(messageBytes, 0, inputBuffer, messageBytes.Length);
            IntPtr outputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            uint bytesReturned;


            bool result = WinApi.DeviceIoControl(
                hDrv,
                WinApi.BUILD_CTL_CODE(FILE_DEVICE_UNKNOWN, FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS),
                inputBuffer,
                (uint)messageBytes.Length,
                outputBuffer,
                (uint)messageBytes.Length,
                out bytesReturned,
                IntPtr.Zero
                );

            timeStampButton.Enabled = false;
            NopButton.Enabled = false;
            XorButton.Enabled = false;
            AddButton.Enabled = false;

            this.vm.functionChosen = "XOR";
            this.vm.CreateLable();
        }
        private void AddButton_Click(object sender, EventArgs e)
        {
            string message = "ADD";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            IntPtr inputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            Marshal.Copy(messageBytes, 0, inputBuffer, messageBytes.Length);
            IntPtr outputBuffer = Marshal.AllocHGlobal(messageBytes.Length);
            uint bytesReturned;


            bool result = WinApi.DeviceIoControl(
                hDrv,
                WinApi.BUILD_CTL_CODE(FILE_DEVICE_UNKNOWN, FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS),
                inputBuffer,
                (uint)messageBytes.Length,
                outputBuffer,
                (uint)messageBytes.Length,
                out bytesReturned,
                IntPtr.Zero
                );

            timeStampButton.Enabled = false;
            NopButton.Enabled = false;
            XorButton.Enabled = false;
            AddButton.Enabled = false;

            this.vm.functionChosen = "ADD";
            this.vm.CreateLable();
        }


        private void timeStampButton_MouseLeave(object sender, EventArgs e)
        {
            rdstInfoLabel.Visible = false;
        }      
        private void timeStampButton_MouseMove(object sender, MouseEventArgs e)
        {
            rdstInfoLabel.Visible = true;
        }      
        private void NopButton_MouseMove(object sender, MouseEventArgs e)
        {
            nopLabel.Visible = true;
        }
        private void NopButton_MouseLeave(object sender, EventArgs e)
        {
            nopLabel.Visible = false;
        }

        private void XorButton_MouseMove(object sender, MouseEventArgs e)
        {
            XorInfoLabel.Visible = true;
        }

        private void XorButton_MouseLeave(object sender, EventArgs e)
        {
            XorInfoLabel.Visible = false;
        }

        private void AddButton_MouseMove(object sender, MouseEventArgs e)
        {
            AddInfoLabel.Visible = true;

        }

        private void AddButton_MouseLeave(object sender, EventArgs e)
        {
            AddInfoLabel.Visible = false;
        }
    }
}
