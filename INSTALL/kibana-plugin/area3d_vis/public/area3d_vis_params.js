import _ from 'lodash';
import { uiModules } from 'ui/modules';
import area3dVisParamsTemplate from 'plugins/area3d_vis/area3d_vis_params.html';

uiModules.get('kibana/area3d_vis')
  .controller('area3dVisParams', ['$scope', function ($scope) {

    $scope.data = {
      graphTypes: [{
        id: 'bar',
        name: 'Bar Graph'
      }, {
        id: 'bar-color',
        name: 'Bar Colored'
      }, {
        id: 'bar-size',
        name: 'Bar Size'
      }, {
        id: 'dot',
        name: 'Dots'
      }, {
        id: 'dot-line',
        name: 'Dos and Lines'
      }, {
        id: 'dot-color',
        name: 'Dots Colored'
      }, {
        id: 'dot-size',
        name: 'Dots Size'
      }, {
        id: 'line',
        name: 'Lines'
      }, {
        id: 'grid',
        name: 'Grid'
      }, {
        id: 'surface',
        name: 'Surface'
      }]
    };

  }])
  .directive('area3dVisParams', function () {
    return {
      restrict: 'E',
      template: area3dVisParamsTemplate,
      link: function ($scope) {

        $scope.$watchMulti([
          'vis.params.graphSelect',
          'vis.params.showPerspective',
          'vis.params.showGrid',
          'vis.params.showShadow',
          'vis.params.keepAspectRatio',
          'vis.params.xLabel',
          'vis.params.yLabel',
          'vis.params.zLabel'
        ], function () {
          if (!$scope.vis) return;
        });
      }
    };
  });
