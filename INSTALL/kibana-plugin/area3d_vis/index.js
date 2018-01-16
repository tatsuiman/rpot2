export default function (kibana) {
  return new kibana.Plugin({
    uiExports: {
      visTypes: [
        'plugins/area3d_vis/area3d_vis'
      ]
    }
  });
}
