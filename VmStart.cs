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
using System.Runtime.InteropServices;



namespace HypervisorApp
{
    public partial class VmStart : Form
    {

        // defenition for IOCTL
        public const uint METHOD_BUFFERED = 0;
        public const uint FILE_DEVICE_UNKNOWN = 0X22;
        public const uint FUNCTION = 0x802;
        public const uint FILE_ANY_ACCESS = 0;
        public const int NUM_VMS_MAX = 3;

        public IntPtr hDrv;
        public int currProccess;
        public Form1 original;
        public IntPtr pCurrActive;
        public GCHandle handle;
        public Label[] vmLabels = new Label[NUM_VMS_MAX];
        public int currVmLabelIndex = 0;

        public const uint ReadWriteAccess = 0xC0000000;
        public const uint ReadWriteShare = 0x00000003;
        public const uint OpenMode = 0x00000003;
        public VmStart(IntPtr hDrv, Form1 original)
        {
            InitializeComponent();
            this.currProccess = 0;
            this.hDrv = hDrv;
            this.original = original;
            // setting pCurrActive to point to zero
            // creating a pointer
            handle = GCHandle.Alloc(0, GCHandleType.Pinned);

            this.pCurrActive = handle.AddrOfPinnedObject();
            vmLabels[0] = vm1;
            vmLabels[1] = vm2;
            vmLabels[2] = vm3;
        }

        private void VmStart_Load(object sender, EventArgs e)
        {

        }

        private void startVmButton_Click(object sender, EventArgs e)
        {
            VirtualMachine vm;
            if (this.currVmLabelIndex > 2)
            {
                int potentialIndex = CheckForEmpty();
                if (potentialIndex == -1)
                {
                    MessageBox.Show("Maxed out number of virtual machines");
                    return;
                }

                vm = new VirtualMachine(vmLabels[potentialIndex]);
                vm.ClearLabel();

                goto continueAfterMax;
            }


            vm = new VirtualMachine(vmLabels[this.currVmLabelIndex]);
            this.currVmLabelIndex++;

            continueAfterMax:

            VM virtualMachineUI = new VM(hDrv, currProccess, pCurrActive, currentActiveLabel, vm);
            virtualMachineUI.Show();
            this.currProccess++;


            Marshal.WriteInt32(this.pCurrActive, Marshal.ReadInt32(this.pCurrActive) + 1);
            currentActiveLabel.Text = $"Active: {Marshal.ReadInt32(pCurrActive)}";




        }
        private int CheckForEmpty()
        {
            for(int i = 0; i < NUM_VMS_MAX; i++)
            {
                if (Convert.ToInt32(vmLabels[i].Tag) != 10)
                {
                    return i;
                }

            }

            return -1;
        }

        private void closeAppButton_Click(object sender, EventArgs e)
        {
            WinApi.CloseHandle(this.hDrv);
            handle.Free();
            this.Close();
            original.Close();
        }
    }

    public class VirtualMachine
    {
        public Label vmStatusLabel;
        public string functionChosen;
        public int originalTag;

        public VirtualMachine(Label vmStatusLabel)
        {
            this.vmStatusLabel = vmStatusLabel;
            this.originalTag = Convert.ToInt32(vmStatusLabel.Tag);
        }
        public void CreateLable()
        {

            vmStatusLabel.Text = $"Virual Machine {vmStatusLabel.Tag}: {functionChosen}, status: Active";
            vmStatusLabel.Visible = true;
            vmStatusLabel.BackColor = Color.SpringGreen;
            vmStatusLabel.Tag = 10;

        }
        public void DeactiveLable()
        {
            vmStatusLabel.Text = $"Virual Machine {vmStatusLabel.Tag}: {functionChosen}, status: Not Active";
            vmStatusLabel.BackColor = Color.LightCoral;
            vmStatusLabel.Tag = this.originalTag;


        }
        public void ClearLabel()
        {
            vmStatusLabel.Text = "";
            vmStatusLabel.Visible = false;
            vmStatusLabel.BackColor = SystemColors.Control;
        }
    }
}
